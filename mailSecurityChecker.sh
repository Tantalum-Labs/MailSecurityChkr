#!/bin/bash
# Usage: ./mailSecurityChecker.sh domains.txt

# ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
ORANGE='\033[38;5;208m'   # Uses 256-color mode
BOLD='\033[1m'
ITALIC='\033[3m'
NC='\033[0m'  # No Color / reset

print_logo() {
    echo -e "${PURPLE}"
    figlet "Mail Security Chkr"
    echo -e "${NC}"
    echo -e "${BLUE}${BOLD}Tantalum Labs 2025${NC}"
    echo -e "${YELLOW}${ITALIC}https://tantalumlabs.io${NC}"
    echo ""
}

# Create the Results directory if it doesn't exist
RESULTS_DIR="./Results"
mkdir -p "$RESULTS_DIR"

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Error: This script must be run as root. Please run with sudo or as root user."
    exit 1
fi

if ! command -v spfquery >/dev/null 2>&1; then
    echo "[-] Error: spfquery is not installed. Please install spfquery to continue."
    exit 1
fi

# Function to perform SPF lookup, check for SPFBreak, check validity of included IPs and verify does not exceed max recursion
check_spf() {
    local domain="$1"
    local result=""
    local spf_record
    local all_ips=()
    local checked_includes=()
    local spf_include_depth_violation=0

    export PERL_NET_DNS_DEBUG=0
    export PERL_NET_DNS_SKIP_PTR=1

    spf_record=$(dig TXT "$domain" +short | tr -d '"' | grep -i 'v=spf1')
    if [[ -z "$spf_record" ]]; then
        result+="[-] SPF: ${RED}${BOLD}MISSING${NC} - No SPF record found\n"
        echo -e "$result"
        return
    fi
    result+="[+] SPF Record: ${CYAN}$spf_record${NC}\n"

    resolve_spf_includes() {
        local include_domain="$1"
        local depth="${2:-1}"

        if [[ $depth -gt 10 ]]; then
            spf_include_depth_violation=1
            result+="  [-] Recursion depth ${RED}EXCEEDED${NC} - culprit ${include_domain} (depth $depth)\n"
            return
        fi

        if [[ " ${checked_includes[*]} " =~ " ${include_domain} " ]]; then
            return
        fi

        checked_includes+=("$include_domain")
        local record
        record=$(dig TXT "$include_domain" +short | tr -d '"' | grep -i 'v=spf1')
        if [[ -z "$record" ]]; then
            result+="  [!] Include is ${ORANGE}INVALID${NC} - culprit ${include_domain} returned no SPF record\n"
            return
        fi

        result+="  [+] ${include_domain} (depth $depth): ${CYAN}$record${NC}\n"

        mapfile -t extracted_ips < <(echo "$record" | grep -oE 'ip[46]:[^ ]+')
        all_ips+=("${extracted_ips[@]}")

        mapfile -t includes < <(echo "$record" | grep -oE 'include:[^ ]+' | cut -d: -f2)
        for inc in "${includes[@]}"; do
            resolve_spf_includes "$inc" $((depth + 1))
        done
    }

    mapfile -t top_ips < <(echo "$spf_record" | grep -oE 'ip[46]:[^ ]+')
    all_ips+=("${top_ips[@]}")

    mapfile -t top_includes < <(echo "$spf_record" | grep -oE 'include:[^ ]+' | cut -d: -f2)
    for inc in "${top_includes[@]}"; do
        resolve_spf_includes "$inc" 1
    done

    if [[ $spf_include_depth_violation -eq 1 ]]; then
        result+="[-] SPF Include Depth Check: ${RED}${BOLD}FAIL${NC} – one or more include chains exceed 10 levels\n"
    else
        result+="[+] SPF Include Depth Check: ${GREEN}${BOLD}PASS${NC} – all include chains ≤ 10 levels\n"
    fi

    if [[ "${#top_ips[@]}" -gt 0 ]]; then
        result+="[!] SPFBreak Vulnerability Check: ${RED}${BOLD}POTENTIAL ISSUE${NC} – ip4/ip6 declared directly in domain's SPF\n"
    else
        result+="[+] SPFBreak Vulnerability Check: ${GREEN}${BOLD}PASS${NC} – no top-level ip4/ip6 entries\n"
    fi

    local pass_count=0
    local warn_count=0
    local fail_count=0

    for ip_entry in "${all_ips[@]}"; do
        ip_block=${ip_entry#*:}
        test_ip=""

        if [[ "$ip_block" =~ "/" ]]; then
            if [[ "$ip_block" =~ ":" ]]; then
                test_ip=$(echo "$ip_block" | sed 's|/.*||')
            else
                test_ip=$(python3 -c "import ipaddress; net=ipaddress.IPv4Network('$ip_block', strict=False); print(next(net.hosts()))" 2>/dev/null)
            fi
        else
            test_ip="$ip_block"
        fi

        if [[ -z "$test_ip" ]]; then
            ((warn_count++))
            continue
        fi

        test_output=$(spfquery --scope mfrom \
            --identity test@"$domain" \
            --ip-address "$test_ip" \
            --helo-identity mail."$domain" -m 0 2>&1)

        if echo "$test_output" | grep -qi "pass"; then
            ((pass_count++))
        elif echo "$test_output" | grep -qi "getnameinfo - ai_family not supported"; then
            ((warn_count++))
        else
            result+="[-] $ip_entry → $test_ip - ${RED}FAIL${NC} - ${RED}$test_output${NC}\n"
            ((fail_count++))
        fi
    done

    result+="[+] SPF IP Validation: ${GREEN}${BOLD}${pass_count} OK${NC}, ${ORANGE}${BOLD}${warn_count} WARN${NC}, ${RED}${BOLD}${fail_count} FAIL${NC}\n"

    echo -e "$result"
}

# Function to perform DMARC lookup and evaluate the arguments
check_dmarc() {
    local domain="$1"
    local dmarc_record
    local result=""
    local pass_count=0
    local warn_count=0
    local fail_count=0

    dmarc=$(dig TXT "_dmarc.${domain}" +short | tr -d '"' | tr -d '\n' | tr '[:upper:]' '[:lower:]' | xargs)

    if [[ -n "$dmarc" ]]; then
        result+="[+] DMARC: ${GREEN}${BOLD}FOUND${NC}\n"
        result+="${CYAN}$dmarc${NC}\n"
    else
        result+="[-] DMARC: ${RED}${BOLD}MISSING${NC} - No DMARC record found${NC}\n\n"
        echo -e "$result"
        return
    fi

    local p=$(echo "$dmarc" | grep -oE '(^|[;[:space:]])p=[^; ]+' | grep -oE 'p=[^; ]+' | cut -d= -f2 | sed 's/ //g')
    local sp=$(echo "$dmarc" | grep -oE 'sp=[^; ]+' | cut -d= -f2 | sed 's/ //g')
    local rua=$(echo "$dmarc" | grep -oE 'rua=[^; ]+' | cut -d= -f2 | sed 's/ //g')
    local ruf=$(echo "$dmarc" | grep -oE 'ruf=[^; ]+' | cut -d= -f2 | sed 's/ //g')
    local fo=$(echo "$dmarc" | grep -oE 'fo=[^; ]+' | cut -d= -f2 | sed 's/ //g')
    local pct=$(echo "$dmarc" | grep -oE 'pct=[^; ]+' | cut -d= -f2 | sed 's/ //g')
    local aspf=$(echo "$dmarc" | grep -oE 'aspf=[^; ]+' | cut -d= -f2 | sed 's/ //g')
    local adkim=$(echo "$dmarc" | grep -oE 'adkim=[^; ]+' | cut -d= -f2 | sed 's/ //g')

    if [[ "$p" == "reject" || "$p" == "quarantine" ]]; then
        result+="  [+] Policy (p): $p - ${GREEN}OK${NC}\n"; ((pass_count++))
    elif [[ "$p" == "none" ]]; then
        result+="  [-] Policy (p): $p - ${RED}NONE${NC}\n"; ((fail_count++))
    else
        result+="  [-] Policy (p) - ${RED}MISSING${NC}\n"; ((fail_count++))
    fi

    if [[ "$sp" == "reject" || "$sp" == "quarantine" ]]; then
        result+="  [+] Subdomain Policy (sp): $sp - ${GREEN}OK${NC}\n"; ((pass_count++))
    elif [[ "$sp" == "none" ]]; then
        result+="  [-] Subdomain Policy (sp): $sp - ${RED}NONE${NC}\n"; ((fail_count++))
    else
        result+="  [!] Subdomain Policy (sp) - ${ORANGE}MISSING${NC}\n"; ((warn_count++))
    fi

    if [[ -n "$rua" ]]; then
        result+="  [+] Aggregate Report URI (rua): $rua - ${GREEN}OK${NC}\n"; ((pass_count++))
    else
        result+="  [!] Aggregate Report URI (rua) - ${ORANGE}MISSING${NC}\n"; ((warn_count++))
    fi

    if [[ -n "$ruf" ]]; then
        result+="  [+] Forensic Report URI (ruf): $ruf - ${GREEN}OK${NC}\n"; ((pass_count++))
    else
        result+="  [!] Forensic Report URI (ruf) - ${ORANGE}MISSING${NC}\n"; ((warn_count++))
    fi

    if [[ "$fo" =~ ^(0|1|d|s|1:|0:|d:|s:|1:0|1:1)$ ]]; then
        result+="  [+] Failure Reporting Options (fo): $fo - ${GREEN}OK${NC}\n"; ((pass_count++))
    elif [[ -z "$fo" ]]; then
        result+="  [!] Failure Reporting Options (fo) - ${ORANGE}MISSING${NC}\n"; ((warn_count++))
    else
        result+="  [-] Failure Reporting Options (fo) - ${RED}INVALID${NC}\n"; ((fail_count++))
    fi

    if [[ "$pct" == "100" || -z "$pct" ]]; then
        result+="  [+] Policy Percentage (pct): ${pct:-100} - ${GREEN}OK${NC}\n"; ((pass_count++))
    else
        result+="  [!] Policy Percentage (pct): $pct - ${ORANGE}less than 100${NC}\n"; ((warn_count++))
    fi

    if [[ "$aspf" == "r" || "$aspf" == "s" ]]; then
        result+="  [+] SPF Alignment Mode (aspf): $aspf - ${GREEN}OK${NC}\n"; ((pass_count++))
    elif [[ -z "$aspf" ]]; then
        result+="  [!] SPF Alignment Mode (aspf): default - ${ORANGE}RELAXED${NC}\n"; ((warn_count++))
    else
        result+="  [-] SPF Alignment Mode (aspf) - ${RED}INVALID${NC}\n"; ((fail_count++))
    fi

    if [[ "$adkim" == "r" || "$adkim" == "s" ]]; then
        result+="  [+] DKIM Alignment Mode (adkim): $adkim - ${GREEN}OK${NC}\n"; ((pass_count++))
    elif [[ -z "$adkim" ]]; then
        result+="  [!] DKIM Alignment Mode (adkim): default - ${ORANGE}RELAXED${NC}\n"; ((warn_count++))
    else
        result+="  [-] DKIM Alignment Mode (adkim) - ${RED}INVALID${NC}\n"; ((fail_count++))
    fi

    result+="[+] Overall DMARC: ${GREEN}${BOLD}${pass_count} OK${NC}, ${ORANGE}${BOLD}${warn_count} WARN${NC}, ${RED}${BOLD}${fail_count} FAIL${NC}\n"

    echo -e "$result"
}

# Function to perform DKIM lookup with common selectors
check_dkim() {
    local domain="$1"
    local selectors=("default" "selector1" "selector2" "google" "k1" "k2" "k3" "mandrill")
    local found_any=0
    local result=""
    for selector in "${selectors[@]}"; do
        local dkim_record
        dkim_record=$(dig TXT "${selector}._domainkey.${domain}" +noall +answer)
        if [[ -n "$dkim_record" ]]; then
            result+="[+] DKIM (${selector}): ${GREEN}${BOLD}FOUND${NC}\n"
            result+="${CYAN}$dkim_record${NC}\n\n"
            found_any=1
        fi
    done
    if [ $found_any -eq 0 ]; then
        result+="[-] DKIM: ${RED}${BOLD}MISSING${NC} - No records for common selectors${NC}\n\n"
    fi
    echo -e "$result"
}

# Function to perform a DNSSEC test for a domain
check_dnssec() {
    local domain="$1"
    local result=""
    local dnskey
    local ds
    dnskey=$(dig DNSKEY "$domain" +short)
    if [[ -n "$dnskey" ]]; then
        result+="[+] DNSKEY: ${GREEN}${BOLD}FOUND${NC}\n"
        result+="${CYAN}$dnskey${NC}\n"
    else
        result+="[-] DNSKEY: ${RED}${BOLD}MISSING${NC}\n"
    fi
    ds=$(dig DS "$domain" +short)
    if [[ -n "$ds" ]]; then
        result+="[+] DS: ${GREEN}${BOLD}FOUND${NC}\n"
        result+="${CYAN}$ds${NC}\n"
    else
        result+="[-] DS: ${RED}${BOLD}MISSING${NC}\n"
    fi
    result+="\n"
    echo -e "$result"
}

# Function to perform a universal DNS DANE test using each MX record
# and querying for TLSA records on common SMTP ports.
check_dane() {
    local domain="$1"
    local ports=(25 465 587)
    local result=""
    local overall_found=0
    local mx_records
    mx_records=$(dig MX "$domain" +short)
    if [[ -z "$mx_records" ]]; then
         result+="[~] ${ORANGE}${BOLD}No MX records found for ${domain}, skipping DNS DANE test.${NC}\n"
         echo -e "$result"
         return
    fi
    while IFS= read -r line; do
         local mx_host
         mx_host=$(echo "$line" | awk '{print $2}' | sed 's/\.$//')
         result+="[+] MX: ${CYAN}${BOLD}${mx_host}${NC}\n"
         local found_tlsa=0
         for port in "${ports[@]}"; do
              local tlsa_output
              tlsa_output=$(dig TLSA "_${port}._tcp.${mx_host}" +noall +answer)
              if [[ -n "$tlsa_output" ]]; then
                   result+="  [+] TLSA ${GREEN}${BOLD}FOUND${NC} for port ${port}\n"
                   result+="${CYAN}$tlsa_output${NC}"
                   found_tlsa=1
              else
                   result+="  [-] TLSA ${ORANGE}${BOLD}NOT FOUND${NC} for port ${port}"
              fi
              result+="\n"
         done
         if [ $found_tlsa -eq 1 ]; then
             result+="Overall DNS DANE for ${mx_host}: ${GREEN}${BOLD}ENABLED${NC}\n"
             overall_found=1
         else
             result+="Overall DNS DANE for ${mx_host}: ${RED}${BOLD}NOT ENABLED${NC}\n"
         fi
         result+="-------------------\n"
    done <<< "$mx_records"
    if [ $overall_found -eq 1 ]; then
         result+="Overall DNS DANE for ${domain}: ${GREEN}${BOLD}ENABLED${NC}\n"
    else
         result+="Overall DNS DANE for ${domain}: ${RED}${BOLD}NOT ENABLED${NC}\n"
    fi
    echo -e "$result"
}

check_mta_sts() {
    local domain="$1"
    local result=""
    local pass_count=0
    local warn_count=0
    local fail_count=0

    local mta_sts_txt_record
    local mta_sts_url="https://mta-sts.${domain}/.well-known/mta-sts.txt"

    mta_sts_txt_record=$(dig +short TXT "_mta-sts.${domain}" | tr -d '"')

    if [[ "$mta_sts_txt_record" =~ v=STSv1 ]]; then
        result+="[+] TXT Record:_mta-sts record exists and contains v=STSv1 - ${GREEN}OK${NC}\n"
        ((pass_count++))
    elif [[ -n "$mta_sts_txt_record" ]]; then
        result+="[!] TXT Record: _mta-sts record found, but missing or invalid version - ${ORANGE}OUTDATED${NC}\n"
        ((warn_count++))
    else
        result+="[-] TXT Record: _mta-sts record missing - ${RED}MISSING${NC}\n"
        ((fail_count++))
        echo -e "$result"
        return
    fi

    local http_response
    http_response=$(curl -sSk -D - --max-time 10 "$mta_sts_url")
    local headers=$(echo "$http_response" | sed -n '/^$/q;p')
    local body=$(echo "$http_response" | sed -n '/^$/,$p' | tail -n +2)

    local content_type
    content_type=$(echo "$headers" | grep -i '^Content-Type:' | cut -d: -f2- | tr -d '\r' | xargs)

    if [[ -z "$content_type" ]]; then
        result+="[-] Policy File: mta-sts.txt doesn't look like a MTA-STS policy - ${RED}INVALID${NC}\n"
        ((fail_count++))
        echo -e "$result"
        return
    elif [[ ! "$content_type" =~ ^text/plain ]]; then
        result+="[-] Policy File: mta-sts.txt doesn't look like a MTA-STS policy - ${RED}INVALID${NC}\n"
        ((fail_count++))
        echo -e "$result"
        return
    else
        ((pass_count++))
    fi

    if [[ -z "$body" ]]; then
        result+="[-] Policy File: mta-sts.txt file is empty - ${RED}INVALID${NC}\n"
        ((fail_count++))
        echo -e "$result"
        return
    fi

    local version mode max_age
    local mx_hosts=()

    version=$(echo "$body" | grep -i '^version:' | cut -d: -f2 | xargs)
    mode=$(echo "$body" | grep -i '^mode:' | cut -d: -f2 | xargs)
    mapfile -t mx_hosts < <(echo "$body" | grep -i '^mx:' | cut -d: -f2- | xargs)
    max_age=$(echo "$body" | grep -i '^max_age:' | cut -d: -f2 | xargs)

    if [[ "$version" == "STSv1" ]]; then
        result+="[+] Policy File: version: $version - ${GREEN}OK${NC}\n"; ((pass_count++))
    else
        result+="[-] Policy File: version: missing or invalid (must be STSv1) - ${RED}MISSING OR INVALID${NC}\n"; ((fail_count++))
    fi
    if [[ "$mode" =~ ^(enforce|testing|none)$ ]]; then
        if [[ "$mode" == "enforce" ]]; then
            result+="[+] Policy File: mode: $mode - ${GREEN}OK${NC}\n"; ((pass_count++))
        else
            result+="[!] Policy File: mode: $mode (not enforced) - ${ORANGE}NOT ENFORCED${NC}\n"; ((warn_count++))
        fi
    else
        result+="[-] Policy File: mode: invalid or missing - ${RED}MISSING OR INVALID${NC}\n"; ((fail_count++))
    fi
    if [[ "${#mx_hosts[@]}" -gt 0 ]]; then
        for mx in "${mx_hosts[@]}"; do
            result+="[+] Policy File: mx: $mx - ${GREEN}OK${NC}\n"; ((pass_count++))
        done
    else
        result+="[-] Policy File: mx: no MX hosts declared - ${RED}MISSING${NC}\n"; ((fail_count++))
    fi
    if [[ "$max_age" =~ ^[0-9]+$ && "$max_age" -ge 86400 ]]; then
        result+="[+] Policy File: max_age: $max_age\n - ${GREEN}OK${NC}\n"; ((pass_count++))
    else
        result+="[!] Policy File: max_age: invalid or too low (should be ≥ 86400) - ${ORANGE}INVALID${NC}\n"; ((warn_count++))
    fi

    result+="[+] MTA-STS Validation: ${GREEN}${BOLD}${pass_count} OK${NC}, ${ORANGE}${BOLD}${warn_count} WARN${NC}, ${RED}${BOLD}${fail_count} FAIL${NC}\n"
    echo -e "$result"
}

if [ $# -ne 1 ]; then
    echo -e "${CYAN}Usage:${NC} $0 <domain_list.txt>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo -e "${RED}Error:${NC} File '$1' not found!"
    exit 1
fi

print_logo

while IFS= read -r domain || [ -n "$domain" ]; do
    domain=$(echo "$domain" | xargs)
    if [[ -z "$domain" || "$domain" =~ ^# ]]; then
        continue
    fi

    DOMAIN_DIR="$RESULTS_DIR/$domain"
    mkdir -p "$DOMAIN_DIR"
    OUTPUT_FILE="$DOMAIN_DIR/mailsecurity.txt"

    {
        echo -e "${BLUE}=============================================================="
        echo -e "    ${BOLD}Mail Security Assessment for: ${NC}${PURPLE}${BOLD}${domain}${NC}${BLUE}"
        echo -e "==============================================================${NC}"
        echo ""

        # 1. MX Records
        echo -e "${BLUE}${BOLD}[MX] MX Records${NC}"
        mx_output=$(dig MX "$domain" +noall +answer)
        if [[ -n "$mx_output" ]]; then
            echo -e "${CYAN}$mx_output${NC}"
            echo -e "[+] Overall MX Records: ${GREEN}${BOLD}OK${NC}"
        else
            echo -e "[~] No MX records found for ${ORANGE}${BOLD}${domain}.${NC}"
            echo -e "[~] Overall MX Records: ${ORANGE}${BOLD}MISSING${NC}"
        fi
        echo ""

        # 2. SPF Record
        echo -e "${BLUE}${BOLD}[SPF] SPF Record${NC}"
        spf_output=$(dig TXT "$domain" +noall +answer | grep -Fi "v=spf1")
        if [[ -n "$spf_output" ]]; then
            echo -e "${CYAN}$spf_output${NC}"
            echo -e "[+] Overall SPF Record: ${GREEN}${BOLD}FOUND${NC}"
            echo -e "$(check_spf "$domain")"
        else
            echo -e "[-] No SPF record found for ${ORANGE}${domain}.${NC}"
            echo -e "[-] Overall SPF Record: ${RED}${BOLD}MISSING${NC}"
        fi
        echo ""

        # 3. DKIM Records
        echo -e "${BLUE}${BOLD}[DKIM] DKIM Records${NC}"
        dkim_results=$(check_dkim "$domain")
        echo -e "$dkim_results"
        if echo -e "$dkim_results" | grep -Fqi "MISSING"; then
            echo -e "[-] Overall DKIM Records: ${RED}${BOLD}MISSING${NC}"
        else
            echo -e "[+] Overall DKIM Records: ${GREEN}${BOLD}FOUND${NC}"
        fi
        echo ""

        # 4. DMARC Record
        echo -e "${BLUE}${BOLD}[DMARC] DMARC Record${NC}"
        dmarc_results=$(check_dmarc "$domain")
        echo -e "$dmarc_results"
        echo ""

        # 5. DNSSEC Test
        echo -e "${BLUE}${BOLD}[DNSSEC] DNSSEC Test${NC}"
        dnssec_results=$(check_dnssec "$domain")
        echo -e "$dnssec_results"
        if echo -e "$dnssec_results" | grep -Fqi "MISSING"; then
            echo -e "[-] Overall DNSSEC: ${RED}${BOLD}NOT ENABLED${NC}"
        else
            echo -e "[+] Overall DNSSEC: ${GREEN}${BOLD}ENABLED${NC}"
        fi
        echo ""

        # 6. DNS DANE Test
        echo -e "${BLUE}${BOLD}[DANE] DNS DANE Test${NC}"
        dane_results=$(check_dane "$domain")
        echo -e "$dane_results"
        echo ""

        # 7. MTA-STS Policy
        echo -e "${BLUE}${BOLD}[MTA-STS] MTA-STS Test${NC}"
        mta_sts_results=$(check_mta_sts "$domain")
        echo -e "$mta_sts_results"
        echo ""

    } > "$OUTPUT_FILE" 2>&1

    echo -e "[!] Assessment for ${PURPLE}${domain}${NC} completed. Results saved to ${GREEN}${OUTPUT_FILE}${NC}"
    echo ""
done < "$1"
