"""递归子域名探测 (三级).

功能:
  1. 读 subdomains.data.enc 或自己先做一次 DNS 爆破
  2. 对每个 *级子域名递归爆破 (深度 3)
  3. 合并去重, 附带 IP 解析

输出 (双层加密):
  out/deep.data.enc + out/deep.key.enc
"""
from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver

from _common import get_target, write_encrypted, load_wordlist


try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
except ImportError:
    print("[FATAL] 缺少 cryptography, 请 pip install cryptography", file=sys.stderr)
    sys.exit(1)


def _resolve_ip(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        if answers:
            return answers[0].to_text()
    except Exception:
        return None
    return None


def _parse_prev_subdomains(target: str) -> list[str]:
    """尝试读之前 subdomain 扫描的加密结果."""
    enc = Path(__file__).resolve().parent / "out" / "subdomains.data.enc"
    key_f = Path(__file__).resolve().parent / "out" / "subdomains.key.enc"
    if not enc.exists() or not key_f.exists():
        return []

    pub_b64 = os.environ.get("RECON_RSA_PUBLIC", "")
    priv_pem = _find_private_key()
    if not priv_pem:
        return []

    try:
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        key_enc = key_f.read_bytes()
        aes_key = priv.decrypt(
            key_enc,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        data_enc = enc.read_bytes()
        iv = data_enc[:16]
        ct = data_enc[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
        obj = json.loads(plain)
        subs = obj.get("unique_subdomains", [])
        return [s for s in subs if s != target]
    except Exception as e:
        print(f"  [WARN] 解析前次子域名结果: {e}", file=sys.stderr)
        return []


def _find_private_key() -> bytes | None:
    candidates = [
        os.path.expanduser("~/.recon/recon_private.pem"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return Path(c).read_bytes()
    return None


def _brute_level(domain: str, wordlist: list[str], depth: int, max_depth: int) -> dict[str, str]:
    """对 domain 做一级 DNS 爆破, 返回 {fqdn: ip}."""
    found: dict[str, str] = {}
    results: list[tuple[str, str]] = []

    def probe(sub: str) -> tuple[str, str | None]:
        fqdn = f"{sub}.{domain}"
        ip = _resolve_ip(fqdn)
        if ip:
            return fqdn, ip
        return fqdn, None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(probe, sub): sub for sub in wordlist}
        for fut in as_completed(futs):
            fqdn, ip = fut.result()
            if ip:
                results.append((fqdn, ip))

    for fqdn, ip in results:
        found[fqdn] = ip

    return found


def main() -> int:
    target = get_target()
    print(f"[deep] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    wordlist = load_wordlist("subdomains") or [
        "www", "mail", "ftp", "smtp", "pop3", "ns1", "ns2",
        "webmail", "vpn", "proxy", "gateway",
        "admin", "login", "dashboard", "api", "dev", "staging",
        "test", "beta", "demo", "sandbox",
        "cdn", "static", "assets", "img", "images", "media",
        "blog", "shop", "store", "pay", "payment",
        "app", "mobile", "m",
        "db", "mysql", "redis", "mongo",
        "git", "gitlab", "jenkins", "jira", "wiki", "docs",
        "monitor", "grafana", "prometheus",
        "auth", "sso", "oauth",
        "ns", "dns", "mx", "mail2", "mail3",
        "server", "node", "host", "hosting",
        "backup", "old", "new", "beta2",
        "status", "health", "statuspage",
        "forum", "community", "chat", "support",
        "help", "helpdesk", "ticket",
        "download", "downloads", "upload",
        "open", "public", "private",
        "push", "stream", "streaming",
        "portal", "corp", "office",
        "remote", "access",
        "owa", "exchange", "outlook",
        "autodiscover", "lyncdiscover",
        "sip", "meet", "conf",
        "rtc", "lync", "skype",
        "partner", "partners", "vendor",
        "cdn2", "static2",
        "s", "a", "b", "c", "d",
        "web", "www2", "www3",
    ]
    print(f"[deep] 字典: {len(wordlist)}", file=sys.stderr)

    prev_subs = _parse_prev_subdomains(target)
    if prev_subs:
        print(f"[deep] 已知子域名: {len(prev_subs)} 个", file=sys.stderr)
    else:
        prev_subs = []
        print(f"[deep] 无已知子域名, 从根开始", file=sys.stderr)

    all_found: dict[str, str] = {}
    scanned_hosts: set[str] = set()

    for depth in range(1, 4):
        if depth == 1:
            targets = [target]
        elif depth == 2:
            targets = [s for s in list(all_found.keys()) + prev_subs
                       if s.count(".") == 1 and s.endswith(target)]
        else:
            targets = [s for s in list(all_found.keys())
                       if s.count(".") == 2 and s.endswith(target)]

        targets = [t for t in targets if t not in scanned_hosts]
        if not targets:
            continue

        print(f"\n[deep] depth={depth}, targets={len(targets)}", file=sys.stderr)

        for host in targets:
            scanned_hosts.add(host)
            found = _brute_level(host, wordlist, depth, 3)
            if found:
                print(f"  {host}: +{len(found)}", file=sys.stderr)
                all_found.update(found)

    elapsed = time.time() - t0
    print(f"\n[deep] 总数: {len(all_found)}, {elapsed:.1f}s", file=sys.stderr)

    by_depth: dict[str, list[str]] = {"1": [], "2": [], "3+": []}
    for fqdn in all_found:
        n = fqdn.count(".")
        if n == 1:
            by_depth["1"].append(fqdn)
        elif n == 2:
            by_depth["2"].append(fqdn)
        else:
            by_depth["3+"].append(fqdn)

    write_encrypted("deep", {
        "target": target,
        "subdomains": sorted(all_found.keys()),
        "resolved": all_found,
        "by_depth": by_depth,
        "total": len(all_found),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())