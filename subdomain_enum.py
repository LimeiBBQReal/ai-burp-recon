"""子域名枚举 — DNS 字典爆破 + crt.sh 查询."""
from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver

from _common import get_target, write_encrypted, load_wordlist, http_get


def resolve_subdomain(sub: str, domain: str) -> str | None:
    fqdn = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
        if answers:
            return f"{fqdn} -> {answers[0].to_text()}"
    except Exception:
        return None
    return None


def query_crtsh(domain: str) -> list[str]:
    """crt.sh 子域名查询."""
    url = f"https://crt.sh/?q={domain}&output=json"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return []
    try:
        data = r.json()
        subs = set()
        for item in data:
            name = item.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subs.add(sub)
        return sorted(subs)
    except Exception as e:
        print(f"  [WARN] crt.sh parse: {e}", file=sys.stderr)
        return []


def main() -> int:
    target = get_target()
    print(f"[subdomain] 目标: {target}", file=sys.stderr)

    wordlist = load_wordlist("subdomains") or [
        "www", "mail", "ftp", "smtp", "ns1", "webmail",
        "login", "admin", "dashboard", "api", "dev", "staging",
        "test", "beta", "demo", "sandbox",
        "cdn", "static", "assets", "img", "images", "media",
        "blog", "shop", "store", "pay", "payment",
        "app", "mobile", "m",
        "vpn", "proxy", "gateway",
        "db", "mysql", "redis", "mongo",
        "git", "gitlab", "jenkins",
        "jira", "wiki", "docs",
        "monitor", "grafana", "prometheus",
        "auth", "sso", "oauth",
    ]
    print(f"[subdomain] 字典: {len(wordlist)}", file=sys.stderr)

    t0 = time.time()
    found: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {
            ex.submit(resolve_subdomain, sub, target): sub
            for sub in wordlist
        }
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                found[r.split(" -> ")[0]] = r.split(" -> ")[1]
                print(f"  [HIT] {r}", file=sys.stderr)

    dns_elapsed = time.time() - t0

    print(f"\n[subdomain] DNS 爆破: {len(found)}/{len(wordlist)}, {dns_elapsed:.1f}s", file=sys.stderr)

    print("[subdomain] crt.sh 查询...", file=sys.stderr)
    crt_subs = query_crtsh(target)
    crt_resolved: dict[str, str] = {}
    if crt_subs:
        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {
                ex.submit(resolve_subdomain, sub.replace(f".{target}", ""), target): sub
                for sub in crt_subs if sub != target
            }
            for fut in as_completed(futs):
                r = fut.result()
                if r:
                    crt_resolved[r.split(" -> ")[0]] = r.split(" -> ")[1]
        print(f"  crt.sh: {len(crt_subs)} 子域名, 可解析 {len(crt_resolved)}", file=sys.stderr)

    all_subs = {**found, **crt_resolved}

    write_encrypted("subdomains", {
        "target": target,
        "dns_brute_found": len(found),
        "crtsh_total": len(crt_subs),
        "crtsh_resolved": len(crt_resolved),
        "unique_subdomains": sorted(all_subs.keys()),
        "resolved": all_subs,
        "elapsed_s": round(time.time() - t0, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())