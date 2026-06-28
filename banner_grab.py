"""Banner 抓取 — 服务指纹."""
from __future__ import annotations

import sys
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from _common import get_target, write_encrypted

PROBES = {
    21: b"",
    22: b"",
    25: b"EHLO test\r\n",
    80: b"GET / HTTP/1.0\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"",
}


def grab_banner(host: str, port: int, timeout: float = 3.0) -> dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        try:
            s.settimeout(2)
            banner = s.recv(1024)
        except socket.timeout:
            banner = b""

        probe = PROBES.get(port, b"")
        response = b""
        if probe:
            try:
                s.sendall(probe)
                s.settimeout(2)
                response = s.recv(4096)
            except Exception:
                response = b""

        s.close()

        return {
            "port": port,
            "banner": banner.decode("utf-8", errors="replace").strip()[:500],
            "response": response.decode("utf-8", errors="replace").strip()[:500],
        }
    except Exception as e:
        return {"port": port, "error": str(e)}


def main() -> int:
    target = get_target()
    print(f"[banner] 目标: {target}", file=sys.stderr)

    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        print(f"[FATAL] 解析失败: {e}", file=sys.stderr)
        return 1

    ports_to_scan = [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379, 9200, 27017]

    t0 = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(grab_banner, ip, port): port for port in ports_to_scan}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            if "banner" in r and r["banner"]:
                print(f"  [{r['port']}] {r['banner'][:80]}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[banner] 完成, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("banners", {
        "target": target,
        "ip": ip,
        "results": results,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())