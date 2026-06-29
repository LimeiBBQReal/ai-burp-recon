"""C-segment scan using authoritative DNS results.

Reads encrypted dns_authoritative output (out/dns_authoritative.data.enc),
scans /24 C-segment for each target IP via TCP connect on ports 80 and 443,
grabs HTTP titles, and performs crt.sh reverse lookup for side-by-side domains.

Output:
  out/cidr_scan.data.enc + .key.enc
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from _common import get_target, write_encrypted, http_get, _read_encrypted

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "out"


def _load_target_ips() -> set[str]:
    ips: set[str] = set()
    for name in ("dns_authoritative", "dns"):
        try:
            obj = _read_encrypted(name)
        except (SystemExit, Exception):
            continue
        if not obj:
            continue
        raw_ips = obj.get("target_ips", [])
        if isinstance(raw_ips, list):
            for ip in raw_ips:
                if isinstance(ip, str):
                    ips.add(ip)
        records = obj.get("records", {})
        if isinstance(records, dict):
            for domain, recs in records.items():
                if isinstance(recs, list):
                    for rec in recs:
                        if isinstance(rec, dict) and rec.get("type") == "A" and not rec.get("wildcard"):
                            ips.add(rec["value"])
        if ips:
            return ips

    if not ips:
        try:
            target = get_target()
            ip = socket.gethostbyname(target)
            ips.add(ip)
        except Exception as e:
            print(f"[FATAL] 无可用 IP: {e}", file=sys.stderr)
            sys.exit(1)
    return ips


def _tcp_alive(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def _http_title(url: str, timeout: float = 4) -> str | None:
    try:
        r = http_get(url, timeout=timeout, verify=False)
        if r and r.status_code < 500:
            content = r.text
            m = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
                return title[:200] if len(title) > 200 else title
            return f"[{r.status_code}] no title"
        return None
    except Exception:
        return None


def _crt_sh_reverse_lookup(ip: str) -> list[str]:
    url = f"https://crt.sh/?q={ip}&output=json"
    r = http_get(url, timeout=10)
    if not r or r.status_code != 200:
        return []
    try:
        domains: set[str] = set()
        for item in r.json():
            name = item.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", sub):
                    domains.add(sub)
        return sorted(domains)
    except Exception:
        return []


def _scan_neighbor(ip: str, port: int) -> dict[str, Any]:
    result: dict[str, Any] = {"alive": False}
    if _tcp_alive(ip, port, timeout=1.5):
        result["alive"] = True
        result["port"] = port
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}"
        title = _http_title(url)
        if title:
            result["title"] = title
        result["url"] = url
    return result


def _scan_c_segment(base_ip: str, ports: list[int]) -> dict[str, Any]:
    segment: dict[str, Any] = {}
    try:
        net = ipaddress.ip_network(f"{base_ip}/24", strict=False)
    except ValueError:
        return {base_ip: {"error": "invalid IP"}}

    hosts = [str(h) for h in net.hosts()]

    def probe(h: str) -> tuple[str, list[dict[str, Any]]]:
        results: list[dict[str, Any]] = []
        for port in ports:
            info = _scan_neighbor(h, port)
            if info.get("alive"):
                results.append(info)
        return h, results

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(probe, h): h for h in hosts}
        for fut in as_completed(futs):
            h, results = fut.result()
            if results:
                segment[h] = {
                    "ports": [
                        {"port": r["port"], "url": r.get("url", ""), "title": r.get("title")}
                        for r in results
                    ]
                }

    return segment


def main() -> int:
    target = get_target()
    print(f"[cidr_scan] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    target_ips = _load_target_ips()
    if not target_ips:
        print("[FATAL] 没有可扫描的 IP", file=sys.stderr)
        return 1

    print(f"[cidr_scan] 从 DNS 结果加载 IP: {len(target_ips)} 个", file=sys.stderr)
    for ip in sorted(target_ips, key=lambda x: tuple(int(o) for o in x.split("."))):
        print(f"  {ip}", file=sys.stderr)

    scan_ports = [80, 443]
    cidr_map: dict[str, dict[str, Any]] = {}
    neighbor_ips: set[str] = set()
    http_titles: dict[str, str] = {}

    for ip in sorted(target_ips, key=lambda x: tuple(int(o) for o in x.split("."))):
        print(f"[cidr_scan] 扫描 C 段 {ip}/24 ...", file=sys.stderr)
        segment = _scan_c_segment(ip, scan_ports)
        if segment:
            cidr_map[ip] = segment
            for h, info in segment.items():
                neighbor_ips.add(h)
                for p in info.get("ports", []):
                    if p.get("title") and p["url"]:
                        http_titles[p["url"]] = p["title"]
            alive_count = len(segment)
            print(f"  {alive_count} 个存活主机", file=sys.stderr)

    print(f"[cidr_scan] 旁站反查 ...", file=sys.stderr)
    side_by_side: dict[str, list[str]] = {}
    for ip in sorted(neighbor_ips):
        domains = _crt_sh_reverse_lookup(ip)
        if domains:
            side_by_side[ip] = domains
            print(f"  {ip}: {len(domains)} 个域名", file=sys.stderr)
        time.sleep(0.3)

    elapsed = time.time() - t0
    print(f"\n[cidr_scan] 完成, {elapsed:.1f}s", file=sys.stderr)
    print(f"  源 IP: {len(target_ips)}", file=sys.stderr)
    print(f"  邻居 IP: {len(neighbor_ips)}", file=sys.stderr)
    print(f"  HTTP 标题: {len(http_titles)}", file=sys.stderr)
    print(f"  旁站 IP: {len(side_by_side)}", file=sys.stderr)

    write_encrypted("cidr_scan", {
        "target": target,
        "source_ips": sorted(target_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "cidr_map": cidr_map,
        "neighbor_ips": sorted(neighbor_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "http_titles": http_titles,
        "side_by_side": side_by_side,
        "scan_ports": scan_ports,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
