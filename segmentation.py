import argparse
import json
import os
import subprocess
from datetime import datetime
from termcolor import cprint, colored
from tqdm import tqdm
from time import sleep
from scapy.all import IP, GRE, send
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

def get_output_filename(attack_type, segment, target_ip):
    target_dir = os.path.join(BASE_DIR, attack_type)
    os.makedirs(target_dir, exist_ok=True)
    filename = os.path.join(target_dir, f"{attack_type}_{segment.replace('/', '-')}_{target_ip}.txt")
    return filename

def check_compliance_from_file(attack_type, segment, target_ip):
    global non_compliance_found

    filename = get_output_filename(attack_type, segment, target_ip)
    if not os.path.exists(filename):
        log(f"[!] File not found for compliance check: {filename}")
        return

    with open(filename, "r") as f:
        results = f.read()

    filename_prefix = f"{attack_type}_{segment.replace('/', '-')}_{target_ip}"
    target_dir = os.path.dirname(filename)

    if any(state in results.lower() for state in ["open", "filtered", "open|filtered"]):
        cprint(f"[!] NON COMPLIANT: {attack_type} on {target_ip}", "red", attrs=['bold'])
        non_compliance_found = True
        fname = os.path.join(target_dir, f"NO_COMPLIANCE__{filename_prefix}.txt")
    else:
        cprint(f"[+] COMPLIANT: {attack_type} on {target_ip}", "green", attrs=['bold'])
        fname = os.path.join(target_dir, f"cumplimiento_{filename_prefix}.txt")

    with open(fname, "w") as f:
        f.write(results)

    log(f"[{attack_type}] Compliance result saved to: {fname}")

# Attack 1: SYN Scan
def attack_syn_scan(target_ip, segment):
    log(f"[*] Launching SYN Scan on {target_ip} in {segment}")
    
    # Nombre del archivo que nmap usará para guardar resultados directamente
    output_file = get_output_filename("syn_scan", segment, target_ip)

    cmd = [
        "sudo", "nmap", "--stats-every", "2s", "-sS", "-T4", "-Pn", "-n", segment,
        "-oN", output_file
    ]
    cprint(f"root@attacker:~# {' '.join(cmd)}", "white", attrs=["bold"])

    # Ejecutar el comando sin mostrar la salida, solo actualizando la barra
    with tqdm(total=100, desc=f"SYN Scan progress on {target_ip}", bar_format="{l_bar}{bar}| {percentage:3.0f}%", colour="cyan") as pbar:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        output_lines = []
        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            if line:
                output_lines.append(line)
                pbar.update(1 if pbar.n < 100 else 0)

        pbar.n = 100
        pbar.refresh()

    # Leer el archivo para validación de cumplimiento
    with open(output_file, "r") as f:
        output = f.read()

    if not check_compliance(output, "syn_scan", target_ip, segment):
        # Mostrar resultados solo si es NO compliant
        print(output)

# Attack 2: IP Spoofing (ICMP, TCP, UDP) DoS 
def attack_ip_spoofing(target_ip, segment, decoys):
    if not decoys:
        log(f"[!] No decoy IPs provided. Skipping IP Spoofing for {target_ip}")
        return

    spoof_ip = decoys[0]  # Usa la primera IP del array decoys
    log(f"[*] Launching IP Spoofing attacks from {spoof_ip} on {target_ip}")

    # Puertos representativos para cada protocolo
    representative_ports = {
        "TCP": 80,
        "UDP": 53  # común para DNS
    }

    packet_count = 200
    payload_size = 120

    for proto, flags in [("ICMP", ["-1"]), ("TCP", ["-S"]), ("UDP", ["--udp"])]:
        desc = f"IP Spoofing {proto} DoS"

        # Mostrar comando representativo
        example_cmd = [
            "sudo", "hping3", "-c", str(packet_count),
            "-d", str(payload_size), "--flood", "-a", spoof_ip
        ]
        example_cmd += flags
        if proto != "ICMP":
            example_cmd += ["-p", str(representative_ports[proto])]
        example_cmd.append(target_ip)

        cprint("root@attacker:~#", "blue", attrs=["bold"], end=" ")
        print(" ".join(example_cmd))

        # Ejecutar ataque real
        cmd = [
            "sudo", "hping3", "-c", str(packet_count),
            "-d", str(payload_size), "--flood", "-a", spoof_ip
        ]
        cmd += flags
        if proto != "ICMP":
            cmd += ["-p", str(representative_ports[proto])]
        cmd.append(target_ip)

        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Verificación manual del cumplimiento
    check_compliance("SENT spoofed DoS packets (manual verification needed)", "ip_spoofing", target_ip, segment)


# Attack 3: Fragmentation
def attack_fragmentation(target_ip, segment):
    log(f"[*] Launching Fragmentation scan on {target_ip} in {segment}")

    # TCP Scan con fragmentación
    tcp_cmd = ["sudo", "nmap", "--stats-every", "2s", "-sS", "-T4", "-f", "-Pn", "-n", target_ip]
    cprint("root@attacker:~#", "blue", attrs=["bold"], end=" ")
    print(" ".join(tcp_cmd))

    tcp_output_lines = []
    with tqdm(total=100, desc="TCP Fragmentation Scan", bar_format="{l_bar}{bar}| {percentage:3.0f}%", colour="cyan") as pbar:
        process_tcp = subprocess.Popen(tcp_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            line = process_tcp.stdout.readline()
            if line == '' and process_tcp.poll() is not None:
                break
            if line:
                tcp_output_lines.append(line)
                pbar.update(1 if pbar.n < 100 else 0)
        pbar.n = 100
        pbar.refresh()
    tcp_result = ''.join(tcp_output_lines)

    # UDP Scan con fragmentación
    udp_cmd = ["sudo", "nmap", "-sU", "-f", "-Pn", "--top-ports", "100", "--max-retries", "1", "-n", target_ip]
    cprint("root@attacker:~#", "blue", attrs=["bold"], end=" ")
    print(" ".join(udp_cmd))

    udp_output_lines = []
    with tqdm(total=100, desc="UDP Fragmentation Scan", bar_format="{l_bar}{bar}| {percentage:3.0f}%", colour="magenta") as pbar:
        process_udp = subprocess.Popen(udp_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            line = process_udp.stdout.readline()
            if line == '' and process_udp.poll() is not None:
                break
            if line:
                udp_output_lines.append(line)
                pbar.update(1 if pbar.n < 100 else 0)
        pbar.n = 100
        pbar.refresh()
    udp_result = ''.join(udp_output_lines)

    # Combinar resultados
    full_output = f"TCP Scan:\n{tcp_result}\n\nUDP Scan:\n{udp_result}"

    save_results("fragmentation", segment, target_ip, full_output)
    check_compliance(full_output, "fragmentation", target_ip, segment)


# Attack 4: Decoy
def attack_decoy_scan(target_ip, segment, decoys):
    decoy_list = ",".join(decoys[:3]) + ",ME," + ",".join(decoys[3:])
    cmd = [
        "sudo","nmap","--stats-every", "2s","-sS", "-T4", "-Pn", "-n", "-D", decoy_list, target_ip
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    save_results("decoy_scan", segment, target_ip, result.stdout)
    check_compliance(result.stdout, "decoy_scan", target_ip, segment)

# Attack 5: Bad checksum
def attack_badsum(target_ip, segment, decoys):
    decoy_list = ",".join(decoys[:3]) + ",ME," + ",".join(decoys[3:])
    cmd = [
        "sudo", "nmap", "--stats-every", "2s", "-sS", "-T4", "-Pn", "-n", "-D", decoy_list, target_ip
    ]

    log(f"[*] Launching Decoy Scan on {target_ip} in {segment}")
    cprint("root@attacker:~#", "blue", attrs=["bold"], end=" ")
    print(" ".join(cmd))

    output_lines = []
    with tqdm(total=100, desc="Decoy SYN Scan", bar_format="{l_bar}{bar}| {percentage:3.0f}%", colour="cyan") as pbar:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            if line:
                output_lines.append(line)
                pbar.update(1 if pbar.n < 100 else 0)
        pbar.n = 100
        pbar.refresh()

    output = ''.join(output_lines)
    save_results("decoy_scan", segment, target_ip, output)
    check_compliance(output, "decoy_scan", target_ip, segment)

# Attack 6: TTL evasion
def attack_ttl(target_ip, segment):
    cmd = ["sudo", "nmap", "--stats-every", "2s", "-sS", "-Pn", "-T4", "-n", "--ttl", "5", target_ip]

    log(f"[*] Launching TTL Evasion Scan on {target_ip} in {segment}")
    cprint("root@attacker:~#", "blue", attrs=["bold"], end=" ")
    print(" ".join(cmd))

    output_lines = []
    with tqdm(total=100, desc="TTL Evasion Scan", bar_format="{l_bar}{bar}| {percentage:3.0f}%", colour="cyan") as pbar:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            if line:
                output_lines.append(line)
                pbar.update(1 if pbar.n < 100 else 0)
        pbar.n = 100
        pbar.refresh()

    output = ''.join(output_lines)
    save_results("ttl_evasion", segment, target_ip, output)
    check_compliance(output, "ttl_evasion", target_ip, segment)


# Attack 7: MAC Spoof
def attack_mac_spoof(target_ip, segment):
    cmd = [
        "sudo", "nmap", "--stats-every", "2s", "-sS", "-Pn", "-T4", "-n",
        "--spoof-mac", "00:09:5B:00:00:00", target_ip
    ]

    log(f"[*] Launching MAC Spoofing Scan on {target_ip} in {segment}")
    cprint("root@attacker:~#", "blue", attrs=["bold"], end=" ")
    print(" ".join(cmd))

    output_lines = []
    with tqdm(total=100, desc="MAC Spoofing Scan", bar_format="{l_bar}{bar}| {percentage:3.0f}%", colour="cyan") as pbar:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            if line:
                output_lines.append(line)
                pbar.update(1 if pbar.n < 100 else 0)
        pbar.n = 100
        pbar.refresh()

    output = ''.join(output_lines)
    save_results("mac_spoof", segment, target_ip, output)
    check_compliance(output, "mac_spoof", target_ip, segment)

# Attack 8: GRE/IP-in-IP
def attack_gre_ipinip(target_ip, segment):
    log(f"[*] Launching GRE over IP-in-IP attack on {target_ip} in {segment}")

    example_cmd = f"scapy: send(IP(dst='{target_ip}')/GRE()/IP(dst='1.1.1.1'))"
    cprint("root@attacker:~#", "blue", attrs=["bold"], end=" ")
    print(example_cmd)

    # Barra de progreso simulada (ya que el envío es instantáneo)
    with tqdm(total=100, desc="Sending GRE Packet", bar_format="{l_bar}{bar}| {percentage:3.0f}%", colour="cyan") as pbar:
        for _ in range(20):
            send(IP(dst=target_ip)/GRE()/IP(dst="1.1.1.1"), verbose=0)
            pbar.update(5)

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
            cprint(f"\n[***] Running {attack_name.upper()} on {target_ip} in {segment}\n", "yellow", attrs=["bold"])
            
            if attack_name in ["ip_spoof", "decoy", "badsum"]:
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
