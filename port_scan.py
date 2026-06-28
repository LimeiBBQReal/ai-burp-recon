"""TCP 端口扫描 — Connect 模式."""
from __future__ import annotations

import sys
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from _common import get_target, write_encrypted

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 465, 587, 636, 873, 989, 990, 993,
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
    target = get_target()
    print(f"[portscan] 目标: {target}", file=sys.stderr)

    try:
        ip = socket.gethostbyname(target)
        print(f"[portscan] 解析: {target} -> {ip}", file=sys.stderr)
    except Exception as e:
        print(f"[FATAL] 解析失败: {e}", file=sys.stderr)
        return 1

    t0 = time.time()
    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=100) as ex:
        futs = {ex.submit(scan_port, ip, port): port for port in TOP_PORTS}
        for fut in as_completed(futs):
            port, is_open = fut.result()
            if is_open:
                open_ports.append(port)
                print(f"  [OPEN] {port}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[portscan] {len(open_ports)} 开放, 耗时 {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("ports", {
        "target": target,
        "ip": ip,
        "tested": len(TOP_PORTS),
        "open_ports": sorted(open_ports),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())