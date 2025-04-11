#!/bin/bash

echo "
 ____      _____         _   
/ ___|    |_   _|__  ___| |_ 
\___ \ _____| |/ _ \/ __| __|
 ___) |_____| |  __/\__ \ |_ 
|____/      |_|\___||___/\__|

"

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m' # Sin color / Reset



# Global variables

status_pentest=true
base_output_dir="attacks_resutls"

# Arguments pasing 

function usage() {
    echo "Usage: $0 --file <json_file> [--attacks syn,frag,decoy,...|all]"
    exit 1
}

FILE=""
ATTACKS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file)
            FILE="$2"
            shift 2
            ;;
        --attacks)
            ATTACKS="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
    echo -e "${RED}[ERROR] Invalid or missing JSON file.${NC}"
    usage
fi

ALL_ATTACKS="syn,frag,decoy,badsum,ttl,mac"
[[ -z "$ATTACKS" || "$ATTACKS" == "all" ]] && ATTACKS="$ALL_ATTACKS"

IFS=',' read -ra ATTACK_LIST <<< "$ATTACKS"

# Declaracion de arrays asociativos

declare -A segments
declare -A targets
declare -A decoys_ips


# Funciones
function capture_segments() {
    local i=1
    for segment in $(jq -r 'keys[]' "$FILE"); do
        local target decoys
        target=$(jq -r --arg seg "$segment" '.[$seg].target' "$FILE")
        decoys=$(jq -r --arg seg "$segment" '.[$seg].decoys | join(",")' "$FILE")

        segments["$i"]="$segment"
        targets["$i"]="$target"
        decoys_ips["$i"]="$decoys"
        ((i++))
    done
}


function prepare_output_dirs() {
    mkdir -p "$base_output_dir/syn_scan"
    mkdir -p "$base_output_dir/ip_spoof_dos"
    mkdir -p "$base_output_dir/fragmentation_scan"
    mkdir -p "$base_output_dir/decoy_scan"
    mkdir -p "$base_output_dir/bad_checksum_scan"
    mkdir -p "$base_output_dir/ttl_evasion_scan"
    mkdir -p "$base_output_dir/mac_spoof_scan"
}

function run_all_scans() {
    for i in "${!segments[@]}"; do
        segment="${segments[$i]}"
        target="${targets[$i]}"
        decoy_list="${decoys_ips[$i]}"
        IFS=',' read -ra decoy_array <<< "$decoy_list"

        echo -e "${PURPLE}>>> Starting Test on $segment <<<${NC}"; echo

        for atk in "${ATTACK_LIST[@]}"; do
            case "$atk" in
                syn)            syn_scan "$segment" ;;
                frag)           fragmentation_scan "$segment" "$target" ;;
                decoy)          decoy_scan "$segment" "$target" "$decoy_list" ;;
                badsum)         bad_checksum_scan "$segment" "$target" "$decoy_list" ;;
                ttl)            ttl_evasion_scan "$segment" ;;
                mac)            mac_spoof_scan "$segment" ;;
                *)              echo -e "${RED}[!] Unknown attack: $atk${NC}" ;;
            esac
        done

        echo -e "${PURPLE}>>> Segment $segment completed <<<${NC}"; echo
    done
}

function syn_scan() {
    local segment="$1"
    local output_syn_scan="$base_output_dir/syn_scan/syn_scan_${segment//\//_}.txt"

    echo -e "${YELLOW}[***] Running SYN scan on $segment${NC}";echo
    echo -e "${BLUE}root@attacker:~# ${NC}sudo nmap -sS --min-rate 5000 -Pn -n $segment -oN $output_syn_scan"

    sudo nmap -sS --min-rate 5000 -Pn -n "$segment" -oN "$output_syn_scan"

    if grep -E "^[0-9]+/(tcp|udp)[[:space:]]+(open|filtered|open\\|filtered)[[:space:]]+" "$output_syn_scan" > /dev/null; then
        echo -e "${RED}[!] NON COMPLIANT: SYN scan on $segment${NC}";echo
        cp "$output_syn_scan" "$base_output_dir/syn_scan/non_compliant_${segment//\//_}.txt"
        status_pentest=false
    else
        echo -e "${GREEN}[+] SYN scan on $segment${NC}";echo
    fi
}

function ip_spoof_dos() {
    #disable for this test
}

function fragmentation_scan() {
    local segment="$1"
    local target="$2"
    local output_fragmentation_scan="$base_output_dir/fragmentation_scan/fragmentation_scan_${segment//\//_}.txt"

    echo -e "${YELLOW}[***] Running fragmented scan on $segment${NC}"; echo
    echo -e "${BLUE}root@attacker:~# ${NC} sudo nmap -sS -T4 -f -Pn -n $target -oN $output_fragmentation_scan${NC}"

    sudo nmap -sS -T4 -f -Pn -n "$target" -oN "$output_fragmentation_scan"

   if grep -E "^[0-9]+/(tcp|udp)[[:space:]]+(open|filtered|open\\|filtered)[[:space:]]+" "$output_fragmentation_scan" > /dev/null; then
        echo -e "${RED}[!] NON COMPLIANT: fragmented scan on $segment${NC}";echo
        cp "$output_fragmentation_scan" "$base_output_dir/fragmentation_scan/non_compliant_${segment//\//_}.txt"
        status_pentest=false
    else
        echo -e "${GREEN}[+] Fragmented scan on $segment${NC}";echo
    fi
}


function decoy_scan() {
    local segment="$1"
    local target="$2"
    local decoys="$3"

    output_decoy_scan="$base_output_dir/decoy_scan/decoy_scan_${segment//\//_}.txt"

    echo -e "${YELLOW}[***] Running decoy scan on $segment${NC}";echo
    echo -e "${BLUE}root@attacker:~# ${NC} sudo nmap -sS -T4 -Pn -n -D \"$decoys\" \"$target\" -oN \"$output_decoy_scan\"${NC}"

    sudo nmap -sS -T4 -Pn -n -D "$decoys" "$target" -oN "$output_decoy_scan"
    

     if grep -E "^[0-9]+/(tcp|udp)[[:space:]]+(open|filtered|open\\|filtered)[[:space:]]+" "$output_decoy_scan" > /dev/null; then
        echo -e "${RED}[!] NON COMPLIANT: Decoy scan on $segment${NC}";echo
        cp "$output_decoy_scan" "$base_output_dir/decoy_scan/non_compliant_${segment//\//_}.txt"
        status_pentest=false
    else
        echo -e "${GREEN}[+] Decoy on $segment${NC}";echo
    fi
}

function bad_checksum_scan() {
    local segment="$1"
    local target="$2"
    local decoys="$3"

    output_bad_checksum_scan="$base_output_dir/bad_checksum_scan/bad_checksum_scan_${segment//\//_}.txt"

    echo -e "${YELLOW}[***] Running Badsum scan on $segment${NC}";echo
    echo -e "${BLUE}root@attacker:~# ${NC} sudo nmap -sS --badsum -T5 -Pn -n $target -oN \"$output_bad_checksum_scan\"${NC}"
   
    sudo nmap -sS --badsum -T5 -Pn -n "$target" -oN "$output_bad_checksum_scan"

     if grep -E "^[0-9]+/(tcp|udp)[[:space:]]+(open|filtered|open\\|filtered)[[:space:]]+" "$output_bad_checksum_scan" > /dev/null; then
        echo -e "${RED}[!] NON COMPLIANT: Badsum scan on $segment${NC}";echo
        cp "$output_bad_checksum_scan" "$base_output_dir/bad_checksum_scan/non_compliant_${segment//\//_}.txt"
    
    else
        echo -e "${GREEN}[+] Badsum scan on $segment${NC}";echo
    fi
}

function ttl_evasion_scan() {
    local segment="$1"
    local output_ttl_evasion_scan="$base_output_dir/ttl_evasion_scan/ttl_evasion_scan_${segment//\//_}.txt"

    echo -e "${YELLOW}[***] Running ttl scan on $segment${NC}"; echo
    echo -e "${BLUE}root@attacker:~# ${NC} sudo nmap -sS --min-rate 5000 -n --ttl 5 $segment -oN $output_ttl_evasion_scan${NC}"

    sudo nmap -sS --min-rate 5000 -Pn -n --ttl 5 "$segment" -oN "$output_ttl_evasion_scan"

    if grep -E "^[0-9]+/(tcp|udp)[[:space:]]+(open|filtered|open\\|filtered)[[:space:]]+" "$output_ttl_evasion_scan" > /dev/null; then
        echo -e "${RED}[!] NON COMPLIANT: ttl evasion scan on $segment${NC}";echo
        cp "$output_ttl_evasion_scan" "$base_output_dir/ttl_evasion_scan/non_compliant_${segment//\//_}.txt"
        status_pentest=false
    else
        echo -e "${GREEN}[+] ttl evasion scan on $segment${NC}";echo
    fi
}

function mac_spoof_scan() {
    local segment="$1"
    local output_mac_spoof_scan="$base_output_dir/mac_spoof_scan/mac_spoof_scan_${segment//\//_}.txt"

    echo -e "${YELLOW}[***] Running MAC Spoof scan on $segment${NC}"; echo
    echo -e "${BLUE}root@attacker:~# ${NC} sudo nmap -sS -Pn -T4 -n --spoof-mac 00:09:5B:00:00:00 $segment -oN $output_mac_spoof_scan${NC}"

    sudo nmap -sS -Pn -T4 -n --spoof-mac 00:09:5B:00:00:00 "$segment" -oN "$output_mac_spoof_scan"

   if grep -E "^[0-9]+/(tcp|udp)[[:space:]]+(open|filtered|open\\|filtered)[[:space:]]+" "$output_mac_spoof_scan" > /dev/null; then
        echo -e "${RED}[!] NON COMPLIANT: MAC Spoof scan on $segment${NC}";echo
        cp "$output_mac_spoof_scan" "$base_output_dir/mac_spoof_scan/non_compliant_${segment//\//_}.txt"
        status_pentest=false
    else
        echo -e "${GREEN}[+] Fragmented scan on $segment${NC}";echo
    fi
}


# Ejecucion
capture_segments
prepare_output_dirs
run_all_scans

if [ "$status_pentest" = true ]; then
    echo
    echo -e "${GREEN}[IMPORTANT]${NC}"
    echo -e "${GREEN}[END] All segments are in compliance [GOOD]${NC}"
    echo
else
    echo
    echo -e "${RED}[IMPORTANT]${NC}"
    echo -e "${RED}[END] All segments are NOT in compliance [BAD]${NC}"
    echo
fi

