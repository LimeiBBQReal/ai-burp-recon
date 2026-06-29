"""Passive subdomain collection from multiple OSINT sources.

Sources (NO DNS queries, unaffected by wildcard DNS):
  - crt.sh Certificate Transparency (JSON API)
  - AlienVault OTX passive_dns
  - Wayback Machine CDX (extract hostnames from URL history)
  - SecurityTrails (free API, best-effort)
  - URLScan.io (public API)

All sources queried in parallel via ThreadPoolExecutor.
Output: flat list of candidate subdomains (deduplicated).

Output:
  out/passive_sources.data.enc + .key.enc
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from _common import get_target, write_encrypted, http_get


def _crt_sh(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        print("  [crt.sh] 请求失败", file=sys.stderr)
        return results
    try:
        for entry in r.json():
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and sub.endswith(f".{domain}"):
                    results.add(sub)
    except Exception as e:
        print(f"  [crt.sh] 解析失败: {e}", file=sys.stderr)
    print(f"  [crt.sh] {len(results)} 条", file=sys.stderr)
    return results


def _otx(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        print("  [OTX] 请求失败", file=sys.stderr)
        return results
    try:
        data = r.json()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "")
            if hostname and hostname.endswith(f".{domain}"):
                results.add(hostname.lower())
    except Exception as e:
        print(f"  [OTX] 解析失败: {e}", file=sys.stderr)
    print(f"  [OTX] {len(results)} 条", file=sys.stderr)
    return results


def _wayback(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    r = http_get(url, timeout=30)
    if not r or r.status_code != 200:
        print("  [Wayback] 请求失败", file=sys.stderr)
        return results
    try:
        data = r.json()
        for row in data[1:]:
            if not row:
                continue
            original_url = row[0] if isinstance(row, list) else str(row)
            if "://" in original_url:
                hostname = original_url.split("://")[1].split("/")[0].split(":")[0].lower()
                if hostname.endswith(f".{domain}"):
                    results.add(hostname)
    except Exception as e:
        print(f"  [Wayback] 解析失败: {e}", file=sys.stderr)
    print(f"  [Wayback] {len(results)} 条", file=sys.stderr)
    return results


def _securitytrails(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        print("  [SecurityTrails] 请求失败 (可能需要 API key)", file=sys.stderr)
        return results
    try:
        data = r.json()
        for sub in data.get("subdomains", []):
            sub = sub.strip().lower()
            if sub:
                results.add(f"{sub}.{domain}")
    except Exception as e:
        print(f"  [SecurityTrails] 解析失败: {e}", file=sys.stderr)
    print(f"  [SecurityTrails] {len(results)} 条", file=sys.stderr)
    return results


def _urlscan(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    r = http_get(url, timeout=20)
    if not r or r.status_code != 200:
        print("  [URLScan] 请求失败", file=sys.stderr)
        return results
    try:
        data = r.json()
        for result in data.get("results", []):
            page = result.get("page", {})
            hostname = page.get("domain", "") or page.get("asn", "")
            if hostname and hostname.endswith(f".{domain}"):
                results.add(hostname.lower())
    except Exception as e:
        print(f"  [URLScan] 解析失败: {e}", file=sys.stderr)
    print(f"  [URLScan] {len(results)} 条", file=sys.stderr)
    return results


def main() -> int:
    target = get_target()
    print(f"[passive] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    sources: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=5) as ex:
        fut_map = {
            ex.submit(_crt_sh, target): "crt.sh",
            ex.submit(_otx, target): "OTX",
            ex.submit(_wayback, target): "Wayback",
            ex.submit(_securitytrails, target): "SecurityTrails",
            ex.submit(_urlscan, target): "URLScan",
        }
        for fut in as_completed(fut_map):
            name = fut_map[fut]
            try:
                sources[name] = sorted(fut.result())
            except Exception as e:
                print(f"  [ERR] {name}: {e}", file=sys.stderr)
                sources[name] = []

    all_candidates: set[str] = set()
    for name, subs in sources.items():
        all_candidates.update(subs)

    merged = sorted(all_candidates)

    elapsed = time.time() - t0
    print(f"\n[passive] 完成, {elapsed:.1f}s", file=sys.stderr)
    print(f"  来源统计:", file=sys.stderr)
    for name, subs in sources.items():
        print(f"    {name}: {len(subs)}", file=sys.stderr)
    print(f"  合并去重后: {len(merged)} 条", file=sys.stderr)

    write_encrypted("passive_sources", {
        "target": target,
        "sources": {k: v for k, v in sources.items()},
        "subdomains": merged,
        "total_unique": len(merged),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
