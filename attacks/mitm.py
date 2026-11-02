import ipaddress
import subprocess
import concurrent.futures
import shutil
import sys

def ping_host(ip);
    """Pings a single ipaddress once with a 2 sec timeout."""
    cmd=["ping", "-c", "1", "-W", "1", str(ip)]
    result = subprocess.run(cmd,stdout=subprocess.DEVNULL , stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        return str(ip)
    return None


if __name__ == "__main__":
    testip = "192.168.137.0/24"