"""PTR reverse-lookup expansion from CIDR scan results.

Reads cidr_scan.data.enc, does PTR on all alive IPs,
discovers new domains, and runs OSINT on each.

Output:
  out/ptr_expanded.data.enc + .key.enc
"""
from __future__ import annotations

import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver

from _common import get_target, write_encrypted, _read_encrypted, http_get

SKIP_DOMAINS = {"knowlespage.com"}


def _ptr_lookup(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0].lower()
        return name
    except Exception:
        return None


def _extract_base(name: str) -> str:
    parts = name.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return name


def _dns_records(domain: str) -> dict[str, Any]:
    out: dict[str, Any] = {"domain": domain}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "SOA"):
        try:
            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            out[rtype] = [str(rr) for rr in answers]
        except Exception:
            out[rtype] = []
    return out


def _crt_sh(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return results
    try:
        for entry in r.json():
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and sub.endswith(f".{domain}"):
                    results.add(sub)
    except Exception:
        pass
    return results


def _wayback(domain: str) -> set[str]:
    results: set[str] = set()
    for limit in (1000,):
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
        r = http_get(url, timeout=15)
        if not r or r.status_code != 200:
            continue
        try:
            data = r.json()
            for row in data[1:]:
                original_url = row[0] if isinstance(row, list) else str(row)
                if "://" in original_url:
                    hostname = original_url.split("://")[1].split("/")[0].split(":")[0].lower()
                    if hostname.endswith(f".{domain}"):
                        results.add(hostname)
        except Exception:
            pass
    return results


def main() -> int:
    t0 = time.time()
    target = get_target()

    cidr = _read_encrypted("cidr_scan")
    alive_ips: set[str] = set()
    for src_ip, neighbors in cidr.get("cidr_map", {}).items():
        for ip in neighbors:
            alive_ips.add(ip)
    alive_ips.update(cidr.get("source_ips", []))
    alive_ips = sorted(alive_ips)
    print(f"[ptr_expand] CIDR 存活 IP: {len(alive_ips)}", file=sys.stderr)

    # Phase A: PTR on all alive IPs
    ip_to_ptr: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(_ptr_lookup, ip): ip for ip in alive_ips}
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                result = fut.result(timeout=10)
                if result:
                    ip_to_ptr[ip] = result
            except Exception:
                pass

    print(f"[ptr_expand] PTR 成功: {len(ip_to_ptr)}/{len(alive_ips)}", file=sys.stderr)
    for ip, name in sorted(ip_to_ptr.items(), key=lambda x: socket.inet_aton(x[0])):
        print(f"  {ip} → {name}", file=sys.stderr)

    # Phase B: Extract base domains
    base_domains: set[str] = set()
    for name in ip_to_ptr.values():
        if not name:
            continue
        base = _extract_base(name)
        if base not in SKIP_DOMAINS and base != target:
            base_domains.add(base)
    base_domains.add(target)
    base_domains = sorted(base_domains)
    print(f"[ptr_expand] 唯一域名: {len(base_domains)}", file=sys.stderr)

    # Phase C: DNS + OSINT per domain
    domain_data: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=len(base_domains)) as ex:
        dns_futs = {ex.submit(_dns_records, d): d for d in base_domains}
        crt_futs = {ex.submit(_crt_sh, d): d for d in base_domains}
        way_futs = {ex.submit(_wayback, d): d for d in base_domains}

        for fut in as_completed(dns_futs):
            d = dns_futs[fut]
            try:
                domain_data[d] = {"dns": fut.result()}
            except Exception as e:
                domain_data[d] = {"dns": {"error": str(e)}}
                print(f"  [ERR] DNS {d}: {e}", file=sys.stderr)

        for fut in as_completed(crt_futs):
            d = crt_futs[fut]
            try:
                subs = fut.result()
                domain_data.setdefault(d, {})["crt_subdomains"] = sorted(subs)
            except Exception:
                pass

        for fut in as_completed(way_futs):
            d = way_futs[fut]
            try:
                subs = fut.result()
                domain_data.setdefault(d, {})["wayback_subdomains"] = sorted(subs)
            except Exception:
                pass

    # Phase D: Merge all subdomains
    all_subdomains: set[str] = set()
    for d, dd in domain_data.items():
        for key in ("crt_subdomains", "wayback_subdomains"):
            for sub in dd.get(key, []):
                all_subdomains.add(sub)

    elapsed = time.time() - t0
    print(f"\n[ptr_expand] 完成, {elapsed:.1f}s", file=sys.stderr)
    print(f"  总子域名: {len(all_subdomains)}", file=sys.stderr)
    print(f"  关联域名: {len(base_domains)}", file=sys.stderr)
    if all_subdomains:
        print(f"  前20: {sorted(all_subdomains)[:20]}", file=sys.stderr)

    write_encrypted("ptr_expanded", {
        "target": target,
        "elapsed_s": round(elapsed, 1),
        "alive_ips": alive_ips,
        "ip_to_ptr": {ip: ptr for ip, ptr in sorted(ip_to_ptr.items(), key=lambda x: socket.inet_aton(x[0]))},
        "discovered_domains": base_domains,
        "domain_data": domain_data,
        "all_subdomains": sorted(all_subdomains),
        "total_subdomains": len(all_subdomains),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
