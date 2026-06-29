from __future__ import annotations

import sys
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from _common import _read_encrypted, write_encrypted

TOP_PORTS = [
    21, 22, 23, 25, 53, 110, 111, 135, 139,
    143, 445, 465, 587, 636, 873, 989, 990, 993,
    995, 1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086,
    2087, 2095, 2096, 2181, 2375, 2376, 3000, 3306, 3389, 3690,
    4000, 4443, 4567, 4848, 5000, 5001, 5432, 5601, 5672, 5900,
    5984, 6379, 6443, 7001, 7002, 7474, 8000, 8008, 8009, 8080,
    8081, 8088, 8089, 8090, 8443, 8500, 8888, 9000, 9001, 9042,
    9090, 9092, 9200, 9300, 9443, 11211, 15672, 27017, 27018, 27019,
    50000, 50070,
]


def scan_port(host: str, port: int, timeout: float = 2.0) -> tuple[int, bool]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return (port, result == 0)
    except Exception:
        return (port, False)


def main() -> int:
    print("[portscan] 读取 verify_subdomains", file=sys.stderr)
    vdata = _read_encrypted("verify_subdomains")
    target = vdata.get("target", "")
    print(f"[portscan] 目标: {target}", file=sys.stderr)

    resolved = vdata.get("resolved", {})
    ips: set[str] = set()
    for sub, ip_list in resolved.items():
        if isinstance(ip_list, list):
            for ip in ip_list:
                ips.add(ip)
        elif isinstance(ip_list, str):
            ips.add(ip_list)
    if not ips:
        for sub, ip in vdata.get("subdomains", {}).items():
            ips.add(ip)

    print(f"[portscan] 待扫描 IP: {len(ips)}", file=sys.stderr)

    t0 = time.time()
    results: dict[str, list[int]] = {}

    for ip in sorted(ips):
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=100) as ex:
            futs = {ex.submit(scan_port, ip, port): port for port in TOP_PORTS}
            for fut in as_completed(futs):
                port, is_open = fut.result()
                if is_open:
                    open_ports.append(port)
        if open_ports:
            results[ip] = sorted(open_ports)
            print(f"  [{ip}] {len(open_ports)} 开放: {open_ports}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[portscan] {len(results)} IP 有开放端口, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("ports", {
        "target": target,
        "ips_scanned": len(ips),
        "ips_with_open": len(results),
        "ports": results,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
