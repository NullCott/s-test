import os
import sys
import json
import subprocess
from termcolor import colored

# Global variables
all_attacks = ["ping", "syn", "fragmentation", "decoys", "ttl", "mac", "udp"] # "ipv6"
status_test = True

# Function for parsing arguments
def parse_arguments():
    import argparse
    parser = argparse.ArgumentParser(description="Segmentation Testing Script")
    parser.add_argument('--file', type=str, required=True, help="Path to JSON file")
    parser.add_argument('--attacks', type=str, default='all', help="Types of attacks to be performed (separated by commas)")
    return parser.parse_args()

# Load and validate JSON
def load_json_file(args):
    if not os.path.isfile(args.file):
        print(colored(f"JSON file does not exist: {args.file}", 'red'))
        sys.exit(1)

    try:
        with open(args.file, 'r') as f:
            json_data = json.load(f)
            if json_data is None:
                print(colored(f"JSON data is empty (None)", 'red'))
                sys.exit(1)
            return json_data
    except json.JSONDecodeError:
        print(colored(f"JSON file with invalid format", 'red'))
        sys.exit(1)
    except Exception as e:
        print(colored(f"Error loading JSON file: {str(e)}", 'red'))
        sys.exit(1)

# Function to proccess attacks
def get_attacks(args):
    if args.attacks == 'all':
        return all_attacks

    attack_list = args.attacks.split(',')
    if len(attack_list) < 2:
        print(colored("Only one attack type provided, defaulting to 'all' attacks", 'yellow'))
        return all_attacks
    return attack_list

# Function to capture segments from JSON
def capture_segments(json_data):
    segments = []
    targets = {}
    decoys_ips = {}

    for segment in json_data:
        segments.append(segment)
        targets[segment] = json_data[segment].get('target')
        decoys_ips[segment] = json_data[segment].get('decoys', [])

    return segments, targets, decoys_ips

# Prepare output directories
def prepare_output_dirs():
    base_dir = "output"
    os.makedirs(os.path.join(base_dir, "ping"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "syn"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "fragmentation"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "decoys"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "ttl"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "mac"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "udp"), exist_ok=True)
    os.makedirs(os.path.join(base_dir, "ipv6"), exist_ok=True)


# ping sweep
def run_ping_sweep(segment,output_dir):
    output_file = os.path.join(output_dir, f"{segment.replace('/', '_')}_ping.txt")
    command = f"sudo nmap -sn -n -T4 {segment} -oN {output_file}"
    try:
        print(colored(f"\n[+] Execuring PING scan for the segment {segment}", 'yellow'))
        print(f"{colored('root@kali:~#', 'green')} {command}") 
        subprocess.run(command, shell=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Error while executing PING scan {segment}: {e}", 'red'))
        return None


# Half-open scan
def run_syn_scan(segment, output_dir):
    output_file = os.path.join(output_dir, f"{segment.replace('/', '_')}_syn.txt")
    command = f"sudo nmap -sS -T4 -Pn -n {segment} -oN {output_file}"
    try:
        print(colored(f"\n[+] Executing SYN scan for the segment {segment}", 'yellow'))
        print(f"{colored('root@kali:~#', 'green')} {command}") 
        subprocess.run(command, shell=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Error while executing SYN scan{segment}: {e}", 'red'))
        return None

# Packet Fragmentation
def run_fragmentation_scan(segment,targets, output_dir): 
    target = targets[segment]
    output_file = os.path.join(output_dir, f"{segment.replace('/', '_')}_fragmentation.txt")
    command = f"sudo nmap -sS -f -Pn -n {target} -oN {output_file}"
    try:
        print(colored(f"\n[+] Executing FRAGMENTATION scan for the segment {segment}", 'yellow'))
        print(f"{colored('root@kali:~#', 'green')} {command}") 
        subprocess.run(command, shell=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Error while executing FRAGMENTATION scan{segment}: {e}", 'red'))
        return None


# Decoy Scan
def run_decoy_scan(segment,targets,decoys_ips,output_dir): 
    target = targets[segment]
    decoys = decoys_ips.get(segment, [])
    if len(decoys) >= 2:
        ordered = decoys[:2] + ["ME"] + decoys[2:]
    else:
        ordered = decoys + ["ME"]

    decoy_list = ",".join(ordered)

    output_file = os.path.join(output_dir, f"{segment.replace('/', '_')}_decoys.txt")
    command = f"sudo nmap -sS -T4 -D {decoy_list} -Pn -n {target} -oN {output_file}"
    try:
        print(colored(f"\n[+] Executing Decoys scan for the segment {segment}", 'yellow'))
        print(f"{colored('root@kali:~#', 'green')} {command}") 
        subprocess.run(command, shell=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Error while executing Decoys scan{segment}: {e}", 'red'))
        return None

# TTL manipulation
def run_ttl_scan(segment,targets, output_dir): 
    target = targets[segment]
    ttl_values = range(2,9,2) 
    output_file = os.path.join(output_dir, f"{segment.replace('/', '_')}_ttl.txt")

    print(colored(f"\n[+] Executing TTL scan for the segment {segment}", 'yellow'))

    for ttl in ttl_values: 
        header = f"\n{'='*20} TTL = {ttl} {'='*20}\n"
        with open(output_file, 'a') as f:
            f.write(header)

        command = f"sudo nmap -sS --ttl {ttl} -T4 -Pn -n {segment}"

        print(f"{colored('root@kali:~#', 'green')} {command} >> {output_file}") 
        try:
            with open(output_file, 'a') as f:
                subprocess.run(command, shell=True, check=True, stdout=f, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(colored(f"[!] Error while executing TTL scan{segment}: {e}", 'red'))
    
    return output_file

# MAC spoofing
def run_mac_scan(segment,targets, output_dir): 
    target = targets[segment]
    output_file = os.path.join(output_dir, f"{segment.replace('/', '_')}_mac.txt")
    command = f"sudo nmap -sS -T4 -Pn -n --spoof-mac 00:75:72:61:5F:02 {segment} -oN {output_file}"
    try:
        print(colored(f"\n[+] Executing MAC spoofing scan for the segment {segment}", 'yellow'))
        print(f"{colored('root@kali:~#', 'green')} {command}") 
        subprocess.run(command, shell=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Error while executing MAC spoofing  scan{segment}: {e}", 'red'))
        return None


# UDP scan
def run_udp_scan(segment, output_dir):
    output_file = os.path.join(output_dir, f"{segment.replace('/', '_')}_syn.txt")
    command = f"sudo nmap -sU -T4 -Pn --top-ports 100 -n {segment} -oN {output_file}"
    try:
        print(colored(f"\n[+] Executing UDP scan for the segment {segment}", 'yellow'))
        print(f"{colored('root@kali:~#', 'green')} {command}") 
        subprocess.run(command, shell=True, check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        print(colored(f"[!] Error while executing UPP scan{segment}: {e}", 'red'))
        return None


# Function to analyze the result
def analyze_scan_result(segment, file_path):
    if not os.path.isfile(file_path):
        print(colored(f"[!] Results file not found: {file_path}", 'red')) 
        return

    with open(file_path, 'r') as f:
        lines = f.readlines()

    open_ports = False
    filtered_ports = False
    closed_ports = False

    for line in lines:
        if "/tcp" in line or "/udp" in line:
            if "open" in line:
                open_ports = True
            elif "filtered" in line:
                filtered_ports = True
            elif "closed" in line:
                closed_ports = True

    if open_ports or filtered_ports:
        print(colored(f"[!] NON COMPLIANT: Some ports are open or filtered on {segment}", 'red'))
        status_test= False  
    else:
        print(colored(f"[+] COMPLIANT: All ports are closed on {segment}", 'green'))
 

# Function to execute all attacks    
def run_all_attacks(segments, targets, decoys_ips, attacks):
    attack_functions = {
        "ping": lambda segment: run_ping_sweep(segment, "output/ping"),
        "syn": lambda segment: run_syn_scan(segment, "output/syn"),
        "fragmentation": lambda segment: run_fragmentation_scan(segment, targets, "output/fragmentation"),
        "decoys": lambda segment: run_decoy_scan(segment,targets,decoys_ips, "output/decoys"),
        "ttl": lambda segment: run_ttl_scan(segment,targets, "output/ttl"),
        "mac": lambda segment: run_mac_scan(segment, targets, "output/mac"),
        "udp": lambda segment: run_udp_scan(segment,"output/udp")
    }

    for segment in segments:
        print(colored(f"\n>>> Starting test on segment {segment} <<<\n", 'magenta'))

        for attack in attacks:
            #if attack not in attack_functions:
            #   print(colored(f'[!]Unknown attack: {attack}', 'red'))
            #   continue

            result = attack_functions[attack](segment)

            if result and attack in ["ping", "syn", "fragmentation","decoys","ttl", "mac", "udp"]: 
                analyze_scan_result(segment, result)

        print(colored(f"\n>>> Segment {segment} completed <<<\n", 'magenta'))


# main 
def main():

    print(colored(r"""
 _________       ______________________ ____________________
/   _____/       \__    ___/\_   _____//   _____/\__    ___/
/_____  \   ______ |    |    |    __)_ \_____  \   |    |   
/        \ /_____/ |    |    |        \/        \  |    |   
/_______  /         |____|   /_______  /_______  /  |____|   
        \/                           \/        \/           
""", 'yellow'))
    args = parse_arguments()

    json_data = load_json_file(args)

    attacks = get_attacks(args)

    segments, targets, decoys_ips = capture_segments(json_data)

    prepare_output_dirs()

    run_all_attacks(segments, targets, decoys_ips, attacks)

    if status_test:
        print(colored(r'''
_________  ________      _____ __________.____    .___   _____    __________________
\_   ___ \ \_____  \    /     \\______   \    |   |   | /  _  \   \      \__    ___/
 /    \  \/  /   |   \  /  \ /  \|     ___/    |   |   |/  /_\  \  /   |   \|    |   
 \     \____/    |    \/    Y    \    |   |    |___|   /    |    \/    |    \    |   
  \______  /\_______  /\____|__  /____|   |_______ \___\____|__  /\____|__  /____|   
         \/         \/         \/                 \/           \/         \/       
''', 'green'))
        print(colored("[+] Test completed successfully: ALL segments compliant!", 'green'))
    else:
        print(colored(r'''
 _______   ________            _________  ________      _____ __________.____    .___   _____    __________________
 \      \  \_____  \           \_   ___ \ \_____  \    /     \\______   \    |   |   | /  _  \   \      \__    ___/
 /   |   \  /   |   \   ______ /    \  \/  /   |   \  /  \ /  \|     ___/    |   |   |/  /_\  \  /   |   \|    |   
/    |    \/    |    \ /_____/ \     \____/    |    \/    Y    \    |   |    |___|   /    |    \/    |    \    |   
\____|__  /\_______  /          \______  /\_______  /\____|__  /____|   |_______ \___\____|__  /\____|__  /____|   
        \/         \/                  \/         \/         \/                 \/           \/         \/          
''', 'red'))
        print(colored("[!] Test completed with issues: Some segments are not compliant.", 'red'))

if __name__ == "__main__":
    main()