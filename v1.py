import argparse
import json
import os
import subprocess
from datetime import datetime
from termcolor import cprint, colored
from tqdm import tqdm

import signal
import sys
import atexit
from colorama import init as colorama_init, deinit as colorama_deinit

# Inicializar colorama con autoreset para que los colores no se queden pegados
colorama_init(autoreset=True)

# Función para limpiar la terminal cuando se cierra el script
def cleanup_terminal():
    print("\033[0m", end="")  # Reset manual del color
    colorama_deinit()         # Finaliza colorama correctamente

# Se ejecuta al salir del script normalmente o por excepción
atexit.register(cleanup_terminal)

# Captura de señales (Ctrl+C, etc.)
def handle_interrupt(sig, frame):
    cprint("\n[!] Interrupción detectada. Cerrando de forma segura...", "blue", attrs=["bold"])
    cleanup_terminal()
    sys.exit(0)

signal.signal(signal.SIGINT, handle_interrupt)
signal.signal(signal.SIGTERM, handle_interrupt)


# Create output directory
BASE_DIR = "attack_results"
os.makedirs(BASE_DIR, exist_ok=True)

# Global status flag
non_compliance_found = False

# Timestamp for logging
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file_path = os.path.join(BASE_DIR, f"test_target_completo_{timestamp}.log")
log_file = open(log_file_path, "w")

# Utility function to log and print
def log(msg):
    print(msg)
    log_file.write(msg + "\n")

# Check results for compliance
def check_compliance(results, attack_type, target_ip, segment):
    global non_compliance_found
    target_dir = os.path.join(BASE_DIR, attack_type)
    os.makedirs(target_dir, exist_ok=True)

    filename_prefix = f"{attack_type}_{segment.replace('/', '-')}_{target_ip}"
    if any(state in str(results).lower() for state in ["open", "filtered", "open|filtered"]):
        cprint(f"[!] NON COMPLIANT: {attack_type} on {target_ip}", "red", attrs=['bold'])
        non_compliance_found = True
        fname = os.path.join(target_dir, f"NO_COMPLIANCE__{filename_prefix}.txt")
    else:
        cprint(f"[+] COMPLIANT: {attack_type} on {target_ip}", "green", attrs=['bold'])
        fname = os.path.join(target_dir, f"cumplimiento_{filename_prefix}.txt")

    with open(fname, "w") as f:
        f.write(json.dumps(results, indent=4))
    log(f"[{attack_type}] Scan results saved to: {fname}")

def save_results(attack_type, segment, target_ip, output_data):
    target_dir = os.path.join(BASE_DIR, attack_type)
    os.makedirs(target_dir, exist_ok=True)
    filename = os.path.join(target_dir, f"{attack_type}_{segment.replace('/', '-')}_{target_ip}.txt")
    with open(filename, "w") as f:
        f.write(output_data)
    log(f"[{attack_type}] Scan results saved to: {filename}")


# Attack 1: SYN Scan
def attack_syn_scan(target_ip, segment):
    cmd = ["sudo","nmap", "-sS", "-T4", "-Pn", "-n", segment]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout

    # Guardar los resultados
    save_results("syn_scan", segment, target_ip, output)

    # Verificar cumplimiento
    check_compliance(output, "syn_scan", target_ip, segment)

# Attack 2: IP Spoofing (ICMP, TCP, UDP)
def attack_ip_spoofing(target_ip, segment, decoys):
    if not decoys:
        log(f"[!] No decoy IPs provided. Skipping IP Spoofing for {target_ip}")
        return

    spoof_ip = decoys[0]  # Usa la primera IP del array decoys
    log(f"[*] Launching IP Spoofing attacks from {spoof_ip} on {target_ip}")

    # Lista de puertos comunes representativos
    common_ports = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 443, 445, 993, 995, 3306, 3389]
    packet_count = 3  # cantidad de paquetes por puerto/protocolo

    for proto, flags in [("ICMP", ["-1"]), ("TCP", ["-S"]), ("UDP", ["--udp"])]:
        desc = f"Spoofing {proto}"
        for port in tqdm(common_ports, desc=desc):
            cmd = ["sudo", "hping3", "-c", str(packet_count), "-a", spoof_ip]
            if flags:
                cmd += flags
            if proto != "ICMP":
                cmd += ["-p", str(port)]
            cmd.append(target_ip)
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    check_compliance("SENT spoofed packets (manual check may be needed)", "ip_spoofing", target_ip, segment)

# Attack 3: Fragmentation
def attack_fragmentation(target_ip, segment):
    tcp_cmd = ["sudo","nmap", "-sS", "-T4", "-f", "-Pn", "-n", target_ip]
    udp_cmd = ["sudo","nmap", "-sU", "-f", "-Pn", "--top-ports", "100", "--max-retries", "1", "-n", target_ip]

    tcp_result = subprocess.run(tcp_cmd, capture_output=True, text=True)
    udp_result = subprocess.run(udp_cmd, capture_output=True, text=True)

    # Combinar los resultados en un solo string
    full_output = f"TCP Scan:\n{tcp_result.stdout}\n\nUDP Scan:\n{udp_result.stdout}"

    # Guardar resultados
    save_results("fragmentation", segment, target_ip, full_output)

    # Validar cumplimiento usando string
    check_compliance(full_output, "fragmentation", target_ip, segment)


# Attack 4: Decoy
def attack_decoy_scan(target_ip, segment, decoys):
    decoy_list = ",".join(decoys[:3]) + ",ME," + ",".join(decoys[3:])
    cmd = [
        "sudo","nmap", "-sS", "-T4", "-Pn", "-n", "-D", decoy_list, target_ip
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    save_results("decoy_scan", segment, target_ip, result.stdout)
    check_compliance(result.stdout, "decoy_scan", target_ip, segment)

# Attack 5: Bad checksum
def attack_badsum(target_ip, segment):
    cmd = ["sudo","nmap", "-sS", "-T4", "--badsum", "-Pn", "-n", target_ip]
    result = subprocess.run(cmd, capture_output=True, text=True)

    save_results("badsum", segment, target_ip, result.stdout)
    check_compliance(result.stdout, "badsum", target_ip, segment)

# Attack 6: TTL evasion
def attack_ttl(target_ip, segment):
    cmd = ["sudo","nmap", "-sS", "-Pn", "-T4", "-n", "--ttl", "5", target_ip]
    result = subprocess.run(cmd, capture_output=True, text=True)

    save_results("ttl_evasion", segment, target_ip, result.stdout)
    check_compliance(result.stdout, "ttl_evasion", target_ip, segment)

# Attack 7: MAC Spoof
def attack_mac_spoof(target_ip, segment):
    cmd = [
        "sudo","nmap", "-sS", "-Pn", "-T4", "-n",
        "--spoof-mac", "00:09:5B:00:00:00", target_ip
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    save_results("mac_spoof", segment, target_ip, result.stdout)
    check_compliance(result.stdout, "mac_spoof", target_ip, segment)

# Attack 8: GRE/IP-in-IP
def attack_gre_ipinip(target_ip, segment):
    from scapy.all import IP, GRE, send
    pkt = IP(dst=target_ip)/GRE()/IP(dst="1.1.1.1")
    send(pkt, verbose=0)
    check_compliance("GRE packet sent (manual check needed)", "gre_ipinip", target_ip, segment)

# Parse arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Network Segmentation Testing Script")
    parser.add_argument("--file", required=True, help="JSON file with segments")
    parser.add_argument("--attacks", nargs="+", default="all", help="List of attacks to run")
    return parser.parse_args()

# Load targets JSON
def load_targets(path):
    with open(path, "r") as f:
        return json.load(f)

# Attack dispatcher
ATTACKS = {
    "syn": attack_syn_scan,
    "ip_spoof": attack_ip_spoofing,
    "fragmentation": attack_fragmentation,
    "decoy": attack_decoy_scan,
    "badsum": attack_badsum,
    "ttl": attack_ttl,
    "mac": attack_mac_spoof,
    "gre": attack_gre_ipinip,
}

def main():
    args = parse_args()
    data = load_targets(args.file)

    attacks_to_run = ATTACKS.keys() if args.attacks == ["all"] else args.attacks

    for segment_info in data:
        segment = segment_info["segment"]
        target_ip = segment_info["target"]
        decoys = segment_info.get("decoys", [])

        for attack_name in attacks_to_run:
            cprint(f"[***] Running {attack_name.upper()} on {target_ip} in {segment}", "yellow", attrs=["bold"])
            if attack_name == "decoy":
                ATTACKS[attack_name](target_ip, segment, decoys)
            else:
                if attack_name in ["decoy", "ip_spoof"]:
                    ATTACKS[attack_name](target_ip, segment, decoys)
                else:
                    ATTACKS[attack_name](target_ip, segment)


    log_file.close()
    if non_compliance_found:
        cprint("\n[!] SEGMENTATION NON COMPLIANCE DETECTED", "red", attrs=['bold', 'blink'])
    else:
        cprint("\n[+] SEGMENTATION COMPLIANT", "green", attrs=['bold'])

if __name__ == "__main__":
    main()
