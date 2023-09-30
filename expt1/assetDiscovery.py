from scapy.all import ARP, Ether, srp, IP, ICMP
import socket
import requests
import threading
import concurrent.futures

# Define the target IP range (e.g., 192.168.1.0/24)
target_ip_range = "172.16.40.184/24"

# Port number to name mapping
port_names = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS"
}

def check_ports(ip_address, ports=[21, 22, 23, 25, 80, 110, 143, 161, 443]):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def identify_device_type(open_ports, has_icmp_response):
    if has_icmp_response:
        return "Router"
    elif 80 in open_ports or 443 in open_ports:
        return "Server"
    elif len(open_ports) <= 3:
        return "Router"
    else:
        return "Unknown"

def scan_target(ip_address):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
    result = srp(arp_request, timeout=2, verbose=False)[0]
    
    has_icmp_response = False

    for sent, received in result:
        ip_address = received.psrc
        mac_address = received.hwsrc

        try:
            host_name = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            host_name = "N/A"

        mac_vendor = "N/A"
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}")
            if response.status_code == 200:
                mac_vendor = response.text
        except requests.exceptions.RequestException:
            pass

        open_ports = check_ports(ip_address)
        open_ports_str = ", ".join([f"{port} ({port_names.get(port, 'Unknown')})" for port in open_ports])
        
        device_type = identify_device_type(open_ports, has_icmp_response)

        print(f"IP: {ip_address} | MAC: {mac_address} | Host Name: {host_name} | Manufacturer: {mac_vendor} | Device Type: {device_type} | Open Ports: {open_ports_str}")

        # Send ICMP echo request to check for router response
        icmp_response = sr1(IP(dst=ip_address)/ICMP(), timeout=1, verbose=False)
        if icmp_response:
            has_icmp_response = True

def main():
    print("Scanning...")
    
    # Use multithreading to speed up the scanning process
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        threads = [executor.submit(scan_target, f"172.16.40.{i}") for i in range(1, 255)]

        # Wait for all threads to complete
        concurrent.futures.wait(threads)

if __name__ == "__main__":
    main()




