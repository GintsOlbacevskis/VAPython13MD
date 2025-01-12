import multiprocessing
from scapy.all import IP, TCP, sr1, conf
import sys
import random
from ipaddress import ip_address

# Function to perform SYN scan on a single port
def syn_scan(ip, port):
    conf.verb = 0  # Disable Scapy verbosity
    src_port = random.randint(1024, 65535)  # Random source port
    packet = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")  # SYN packet
    response = sr1(packet, timeout=1, verbose=False)  # Send packet and wait for response

    if response:
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK response
                # Send RST to close connection
                send_rst = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R")
                sr1(send_rst, timeout=1, verbose=False)
                return f"Port {port}: OPEN"
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK response
                return f"Port {port}: CLOSED"
    return f"Port {port}: FILTERED"

# Worker function for multiprocessing
def scan_ports(ip, ports):
    results = []
    for port in ports:
        result = syn_scan(ip, port)
        results.append(result)
    return results

# Function to distribute port scanning across multiple processes
def multiprocess_scan(ip, port_range, num_processes):
    ports = list(port_range)
    chunk_size = len(ports) // num_processes
    port_chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]

    with multiprocessing.Pool(num_processes) as pool:
        tasks = [(ip, chunk) for chunk in port_chunks]
        results = pool.starmap(scan_ports, tasks)

    # Flatten results from all processes
    return [result for sublist in results for result in sublist]

# Main program
if __name__ == "__main__":
    try:
        target_ip = input("Enter target IP address: ").strip()
        port_start = int(input("Enter start port: "))
        port_end = int(input("Enter end port: "))
        num_processes = int(input("Enter number of processes: "))

        # Validate IP address
        try:
            ip_address(target_ip)
        except ValueError:
            print("Invalid IP address.")
            sys.exit(1)

        print(f"Scanning {target_ip} for open ports in range {port_start}-{port_end}...")

        # Perform multiprocessing port scan
        port_range = range(port_start, port_end + 1)
        results = multiprocess_scan(target_ip, port_range, num_processes)

        # Print results
        print("\nScan Results:")
        for result in results:
            print(result)

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)