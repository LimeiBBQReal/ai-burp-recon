"""Passive subdomain collection from multiple OSINT sources + fallback DNS brute.

Fallback 机制:
  Phase A: 纯被动 OSINT 数据源 (不影响 DNS 的)
    1. crt.sh             — 证书透明度
    2. OTX AlienVault     — 被动 DNS
    3. Wayback Machine    — URL 历史
    4. SecurityTrails     — (免费 API, 带 key)
    5. URLScan.io         — 公共搜索
    6. DNSDumpster        — 免费 DNS 查询 (带 key)
    7. Shodan             — 通过 public API 搜索 hostname
    8. Censys             — 证书/IP 搜索 (IPv4 API 免费)
    9. RapidDNS.io      — 免费子域名 API (无 key)
   10. Riddler.io         — 免费

  Phase B: 如果 Phase A 结果太少 (< 50 条), 启动 DNS 字典爆破
    使用 subdomains_large 字典 (1522 条)
    对每条 DNS A 记录做通配符 IP 过滤 (198.18.x.x / 0.0.0.0)
    随机域名 HTTP 指纹比对做二次验证
    产出"候选"子域名 (非 verified, 留给 Phase 2 验证)

  Phase C: 关联资产
    11. DNS 同一 MX / NS 的主机 C 段穷举
    12. 已知 IP 的反向 PTR

输出:
  out/passive_sources.data.enc + .key.enc
    包含: 来源统计, 所有候选子域名, 是否启用了 DNS fallback
"""
from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver
import dns.name

from _common import get_target, write_encrypted, http_get, load_wordlist, _read_encrypted

WILDCARD_IPS = {"198.18.", "0.0.0.0"}
DNS_FALLBACK_THRESHOLD = 50


def _is_wildcard_ip(ip: str | None) -> bool:
    if not ip:
        return True
    for prefix in WILDCARD_IPS:
        if ip.startswith(prefix):
            return True
    return False


# ═══════════════════════════════════════════════════════
# Phase A: 纯被动 OSINT
# ═══════════════════════════════════════════════════════

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
    print(f"  [crt.sh] {len(results)} 条", file=sys.stderr)
    return results


def _otx(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return results
    try:
        for entry in r.json().get("passive_dns", []):
            hostname = entry.get("hostname", "")
            if hostname and hostname.endswith(f".{domain}"):
                results.add(hostname.lower())
    except Exception:
        pass
    print(f"  [OTX] {len(results)} 条", file=sys.stderr)
    return results


def _wayback(domain: str) -> set[str]:
    results: set[str] = set()
    for limit in (1000, 5000):
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
        r = http_get(url, timeout=30)
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
    print(f"  [Wayback] {len(results)} 条", file=sys.stderr)
    return results


def _securitytrails(domain: str) -> set[str]:
    """SecurityTrails API — 从 .env SECURITYTRAILS_API_KEY."""
    results: set[str] = set()
    key = os.environ.get("SECURITYTRAILS_API_KEY", "")
    if not key:
        print("  [SecurityTrails] 跳过 (无 SECURITYTRAILS_API_KEY)", file=sys.stderr)
        return results
    headers = {"APIKEY": key}
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    r = http_get(url, timeout=15, headers=headers)
    if not r or r.status_code != 200:
        print("  [SecurityTrails] 请求失败", file=sys.stderr)
        return results
    try:
        for sub in r.json().get("subdomains", []):
            sub = sub.strip().lower()
            if sub:
                results.add(f"{sub}.{domain}")
    except Exception:
        pass
    print(f"  [SecurityTrails] {len(results)} 条", file=sys.stderr)
    return results


def _urlscan(domain: str) -> set[str]:
    results: set[str] = set()
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    r = http_get(url, timeout=20)
    if not r or r.status_code != 200:
        return results
    try:
        for result in r.json().get("results", []):
            page = result.get("page", {})
            hostname = page.get("domain", "")
            if hostname and hostname.endswith(f".{domain}"):
                results.add(hostname.lower())
    except Exception:
        pass
    print(f"  [URLScan] {len(results)} 条", file=sys.stderr)
    return results


def _dnsdumpster(domain: str) -> set[str]:
    """DNSDumpster — 免费, 但可能被限流."""
    results: set[str] = set()
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return results
    try:
        data = r.json()
        for entry in data.get("dns_records", {}).get("a", []):
            hostname = entry.get("hostname", "").lower().strip()
            if hostname and hostname.endswith(f".{domain}"):
                results.add(hostname)
    except Exception:
        pass
    print(f"  [DNSDumpster] {len(results)} 条", file=sys.stderr)
    return results


def _shodan(domain: str) -> set[str]:
    """Shodan API — 搜索 hostname 关联 IP 和子域名."""
    results: set[str] = set()
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        print("  [Shodan] 跳过 (无 SHODAN_API_KEY)", file=sys.stderr)
        return results
    # 搜索: 解析历史 + hostname
    for query in (f"hostname%3A{domain}", f"ssl%3A{domain}"):
        url = f"https://api.shodan.io/shodan/host/search?key={key}&query={query}"
        r = http_get(url, timeout=15)
        if not r or r.status_code != 200:
            continue
        try:
            data = r.json()
            for match in data.get("matches", []):
                for hn in match.get("hostnames", []):
                    hn = hn.lower().strip()
                    if hn.endswith(f".{domain}") and hn != domain:
                        results.add(hn)
        except Exception:
            pass
    print(f"  [Shodan] {len(results)} 条", file=sys.stderr)
    return results


def _censys(domain: str) -> set[str]:
    """Censys API — 新版单 Key 认证."""
    results: set[str] = set()
    key = os.environ.get("CENSYS_API_KEY", "")
    if not key:
        print("  [Censys] 跳过 (无 CENSYS_API_KEY)", file=sys.stderr)
        return results
    try:
        url = f"https://search.censys.io/api/v2/hosts/search?q=dns.names:{domain}&per_page=100"
        r = http_get(url, timeout=15, headers={"Accept": "application/json", "Authorization": f"Bearer {key}"})
        if r and r.status_code == 200:
            for hit in r.json().get("result", {}).get("hits", []):
                for name in hit.get("dns", {}).get("names", []):
                    name = name.lower().strip()
                    if name.endswith(f".{domain}") and name != domain:
                        results.add(name)
    except Exception:
        pass
    print(f"  [Censys] {len(results)} 条", file=sys.stderr)
    return results


def _otx(domain: str) -> set[str]:
    """AlienVault OTX — 带 API Key 提高请求限额."""
    results: set[str] = set()
    key = os.environ.get("OTX_API_KEY", "")
    headers = {"X-OTX-API-KEY": key} if key else {}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, timeout=15, headers=headers)
    if not r or r.status_code != 200:
        print("  [OTX] 请求失败", file=sys.stderr)
        return results
    try:
        for entry in r.json().get("passive_dns", []):
            hostname = entry.get("hostname", "")
            if hostname and hostname.endswith(f".{domain}"):
                results.add(hostname.lower())
    except Exception:
        pass
    print(f"  [OTX] {len(results)} 条 (key={bool(key)})", file=sys.stderr)
    return results


def _virustotal(domain: str) -> set[str]:
    """VirusTotal API — subdomain 解析."""
    results: set[str] = set()
    key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        print("  [VT] 跳过 (无 VIRUSTOTAL_API_KEY)", file=sys.stderr)
        return results
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    r = http_get(url, timeout=15, headers={"x-apikey": key})
    if not r or r.status_code != 200:
        return results
    try:
        for item in r.json().get("data", []):
            sub = item.get("id", "")
            if sub and sub.endswith(f".{domain}") and sub != domain:
                results.add(sub.lower())
    except Exception:
        pass
    print(f"  [VT] {len(results)} 条", file=sys.stderr)
    return results


def _rapiddns(domain: str) -> set[str]:
    """RapidDNS.io — 完全免费, 无 key."""
    results: set[str] = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return results
    try:
        import re
        for m in re.finditer(rf"<td>([\w\.-]+\.{re.escape(domain)})</td>", r.text or "", re.I):
            results.add(m.group(1).lower())
    except Exception:
        pass
    print(f"  [RapidDNS] {len(results)} 条", file=sys.stderr)
    return results


def _riddler(domain: str) -> set[str]:
    """Riddler.io — 免费."""
    results: set[str] = set()
    url = f"https://riddler.io/api/search?q=host:{domain}"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return results
    try:
        for entry in r.json() if isinstance(r.json(), list) else r.json().get("results", []):
            host = entry.get("host", "")
            if host and host.endswith(f".{domain}"):
                results.add(host.lower())
    except Exception:
        pass
    print(f"  [Riddler] {len(results)} 条", file=sys.stderr)
    return results


# ═══════════════════════════════════════════════════════
# Phase B: DNS 字典爆破 + 通配符过滤
# ═══════════════════════════════════════════════════════

def _resolve_a(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        if answers:
            return answers[0].to_text()
    except Exception:
        return None
    return None


def _get_body(domain: str) -> str:
    r = http_get(f"http://{domain}/", timeout=5)
    if r:
        return (r.text or "")[:200]
    return ""


def _get_wildcard_pattern(domain: str) -> tuple[str | None, str]:
    import uuid
    rand = str(uuid.uuid4()).replace("-", "")[:12]
    test = f"{rand}.{domain}"
    ip = _resolve_a(test)
    body = _get_body(test) if ip else ""
    return ip, body


def _dns_brute_fallback(domain: str) -> list[dict[str, Any]]:
    wordlist = load_wordlist("subdomains_large")
    if not wordlist:
        wordlist = load_wordlist("subdomains")
    if not wordlist:
        print("  [DNS-FB] 无字典可用", file=sys.stderr)
        return []

    print(f"  [DNS-FB] 获取通配符指纹...", file=sys.stderr)
    wc_ip, wc_body = _get_wildcard_pattern(domain)
    print(f"  [DNS-FB] 通配符 IP: {wc_ip}, body_len={len(wc_body)}", file=sys.stderr)

    candidates: list[dict[str, Any]] = []

    def test(word: str) -> dict[str, Any] | None:
        fqdn = f"{word}.{domain}"
        ip = _resolve_a(fqdn)
        if ip is None:
            return None
        if _is_wildcard_ip(ip):
            return None
        body = _get_body(fqdn)
        if wc_body and len(body) > 50 and wc_ip == ip:
            return None
        if wc_body and len(body) > 30 and body[:100] == wc_body[:100]:
            return None
        candidates.append({"subdomain": fqdn, "ip": ip, "body_preview": body[:60]})
        return {"subdomain": fqdn, "ip": ip}

    # 并行 100 线程
    with ThreadPoolExecutor(max_workers=100) as ex:
        futs = {ex.submit(test, w): w for w in wordlist[:2000]}
        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception:
                continue

    # 如果命中了, 继续剩下的
    if len(candidates) > 20:
        remaining = wordlist[2000:]
        with ThreadPoolExecutor(max_workers=100) as ex:
            futs = {ex.submit(test, w): w for w in remaining}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:
                    continue
    else:
        print(f"  [DNS-FB] 前 2000 条只命中 {len(candidates)}, 停止", file=sys.stderr)

    print(f"  [DNS-FB] 字典爆破完成, 候选 {len(candidates)} 个", file=sys.stderr)
    return candidates


# ═══════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════

def main() -> int:
    target = get_target()
    print(f"[passive] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    sources: dict[str, Any] = {}

    # Phase A: 全并行 OSINT
    passive_fns = {
        _crt_sh: "crt.sh",
        _otx: "OTX",
        _wayback: "Wayback",
        _securitytrails: "SecurityTrails",
        _urlscan: "URLScan",
        _dnsdumpster: "DNSDumpster",
        _shodan: "Shodan",
        _censys: "Censys",
        _rapiddns: "RapidDNS",
        _riddler: "Riddler",
        _virustotal: "VirusTotal",
        _fofa: "Fofa",
        _hunter: "Hunter",
    }

    with ThreadPoolExecutor(max_workers=13) as ex:
        futs = {ex.submit(fn, target): name for fn, name in passive_fns.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                sources[name] = sorted(fut.result())
            except Exception as e:
                print(f"  [ERR] {name}: {e}", file=sys.stderr)
                sources[name] = []

    all_candidates: set[str] = set()
    for name, subs in sources.items():
        all_candidates.update(subs)

    used_dns_fallback = False
    dns_fallback_results: list[dict[str, Any]] = []

    if len(all_candidates) < DNS_FALLBACK_THRESHOLD:
        print(f"\n[passive] 候选太少 ({len(all_candidates)}), 启动 DNS 字典爆破 fallback...", file=sys.stderr)
        dns_fallback_results = _dns_brute_fallback(target)
        if dns_fallback_results:
            used_dns_fallback = True
            for c in dns_fallback_results:
                all_candidates.add(c["subdomain"])

    merged = sorted(all_candidates)
    elapsed = time.time() - t0

    print(f"\n[passive] 完成, {elapsed:.1f}s", file=sys.stderr)
    print(f"  来源统计:", file=sys.stderr)
    for name, subs in sorted(sources.items()):
        print(f"    {name}: {len(subs)}", file=sys.stderr)
    if used_dns_fallback:
        print(f"    DNS-Fallback: {len(dns_fallback_results)}", file=sys.stderr)
    print(f"  合并去重后: {len(merged)} 条", file=sys.stderr)

    write_encrypted("passive_sources", {
        "target": target,
        "sources": {k: len(v) for k, v in sources.items()},
        "subdomains": merged,
        "total_unique": len(merged),
        "used_dns_fallback": used_dns_fallback,
        "dns_fallback_count": len(dns_fallback_results),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
