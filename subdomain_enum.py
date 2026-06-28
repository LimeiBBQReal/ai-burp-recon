"""全量增强版子域名枚举 — DNS 字典爆破 + crt.sh + subfinder (16+ 数据源).

功能 (3 层):
  1. DNS 字典爆破 (up to 10000+ 字典)
  2. crt.sh 证书透明度查询
  3. subfinder (ProjectDiscovery) — 自动下载, 聚合 16+ 数据源

输出 (双层加密):
  out/subdomains.data.enc + out/subdomains.key.enc
"""
from typing import Any

import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver

from _common import get_target, write_encrypted, http_get

SUBFINDER_BIN = Path(__file__).resolve().parent / "subfinder"
SUBFINDER_URL = (
    "https://github.com/projectdiscovery/subfinder/releases/latest/download/"
    "subfinder_2.7.0_linux_amd64.zip"
)


def _install_subfinder() -> bool:
    """如果 subfinder 不存在则自动下载."""
    bin_path = SUBFINDER_BIN
    if bin_path.exists():
        return True

    print("  [subfinder] 未找到, 自动下载...", file=sys.stderr)
    import urllib.request
    import zipfile

    zip_path = bin_path.parent / "subfinder_tmp.zip"
    try:
        urllib.request.urlretrieve(SUBFINDER_URL, zip_path)
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if "subfinder" in name and not name.endswith("/"):
                    data = zf.read(name)
                    bin_path.write_bytes(data)
                    bin_path.chmod(0o755)
                    break
        zip_path.unlink(missing_ok=True)
        return bin_path.exists()
    except Exception as e:
        print(f"  [WARN] subfinder 下载失败: {e}", file=sys.stderr)
        if zip_path.exists():
            zip_path.unlink(missing_ok=True)
        return False


def _resolve_subdomain(sub: str, domain: str) -> str | None:
    fqdn = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=3)
        if answers:
            return str(answers[0].to_text())
    except Exception:
        return None
    return None


def _brute_dict(domain: str, wordlist: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}

    def probe(sub: str) -> tuple[str, str | None]:
        ip = _resolve_subdomain(sub, domain)
        return ip

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs_map: dict[Any, str] = {}
        for sub in wordlist:
            futs_map[ex.submit(probe, sub)] = sub
        for fut in as_completed(futs_map):
            ip = fut.result()
            sub = futs_map[fut]
            if ip:
                found[f"{sub}.{domain}"] = ip
    return found


def _crt_sh(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return []
    try:
        subs = set()
        for item in r.json():
            name = item.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subs.add(sub)
        return sorted(subs)
    except Exception as e:
        print(f"  [WARN] crt.sh: {e}", file=sys.stderr)
        return []


def _resolve_many(domains: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}

    def resolve(domain: str) -> tuple[str, str | None]:
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=3)
            if answers:
                return domain, str(answers[0].to_text())
        except Exception:
            pass
        return domain, None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(resolve, d): d for d in domains}
        for fut in as_completed(futs):
            dom, ip = fut.result()
            if ip:
                found[dom] = ip
    return found


def _run_subfinder(domain: str) -> list[str]:
    """调用 subfinder 采集子域名."""
    if not _install_subfinder():
        return []

    cmd = [str(SUBFINDER_BIN), "-d", domain, "-silent"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            subs = [line.strip().lower() for line in r.stdout.splitlines() if line.strip()]
            return sorted(set(subs))
        print(f"  [WARN] subfinder exit={r.returncode}: {r.stderr[:200]}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("  [WARN] subfinder 超时 (120s)", file=sys.stderr)
    except FileNotFoundError:
        print("  [WARN] subfinder 不存在", file=sys.stderr)
    return []


def main() -> int:
    target = get_target()
    print(f"[subdomain] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    # 1. 加载字典
    from _common import load_wordlist
    small_list = load_wordlist("subdomains")
    large_list = load_wordlist("subdomains_large")

    if large_list:
        wordlist = large_list
        print(f"[+] 使用大字典: {len(large_list)} 条", file=sys.stderr)
    else:
        wordlist = small_list
        print(f"[+] 使用小字典: {len(small_list)} 条", file=sys.stderr)

    # 2. DNS 字典爆破
    print(f"[subdomain] DNS 字典爆破 ({len(wordlist)})...", file=sys.stderr)
    dns_found = _brute_dict(target, wordlist)
    print(f"  → {len(dns_found)} 命中", file=sys.stderr)

    # 3. crt.sh 查询
    print("[subdomain] crt.sh 查询...", file=sys.stderr)
    crt_subs = _crt_sh(target)
    print(f"  → {len(crt_subs)} 子域名", file=sys.stderr)

    crt_resolved = _resolve_many(crt_subs)
    print(f"  → 可解析 {len(crt_resolved)}", file=sys.stderr)

    all_subs: dict[str, str] = {**dns_found, **crt_resolved}

    # 4. subfinder
    sf_subs = _run_subfinder(target)
    if sf_subs:
        print(f"[subdomain] subfinder: {len(sf_subs)} 子域名", file=sys.stderr)
        sf_resolved = _resolve_many(sf_subs)
        all_subs.update({s: sf_resolved.get(s, "") for s in sf_subs})

    elapsed = time.time() - t0
    print(f"\n[subdomain] 总计: {len(all_subs)} 子域名, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("subdomains", {
        "target": target,
        "total": len(all_subs),
        "dns_brute_found": len(dns_found),
        "crtsh_found": len(crt_subs),
        "subfinder_found": len(sf_subs) if sf_subs else 0,
        "unique_subdomains": sorted(all_subs.keys()),
        "resolved": {k: v for k, v in all_subs.items() if v},
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())