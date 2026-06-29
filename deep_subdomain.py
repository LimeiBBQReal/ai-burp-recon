"""递归深度子域名探测 (depth=2) — 基于已验证子域名进行 DNS 递归爆破.

流程:
  1. 读取 Phase 2a 的 verify_subdomains.data.enc
  2. 只取 verified=True 的二级子域名 (如 sub.example.com)
  3. 对每个目标, 使用 subdomains_large 字典递归爆破 (depth=2)
  4. 每层进行通配符 IP 过滤
  5. 输出 deep_subdomains 含解析 IP

输出:
  out/deep_subdomains.data.enc + out/deep_subdomains.key.enc
"""
from __future__ import annotations

import json
import os
import sys
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import dns.resolver

from _common import get_target, write_encrypted, load_wordlist

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
except ImportError:
    print("[FATAL] 缺少 cryptography, 请 pip install cryptography", file=sys.stderr)
    sys.exit(1)

WILDCARD_IPS = {"198.18.", "0.0.0.0"}


def _find_private_key() -> bytes | None:
    candidates = [
        os.path.expanduser("~/.recon/recon_private.pem"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return Path(c).read_bytes()
    return None


def _read_encrypted(name: str) -> dict | None:
    p = Path(__file__).resolve().parent
    enc = p / "out" / f"{name}.data.enc"
    key_f = p / "out" / f"{name}.key.enc"
    if not enc.exists() or not key_f.exists():
        print(f"  [WARN] 文件不存在: {enc.name} / {key_f.name}", file=sys.stderr)
        return None

    pub_b64 = os.environ.get("RECON_RSA_PUBLIC", "")
    if not pub_b64:
        print("  [WARN] RECON_RSA_PUBLIC 未设置, 跳过解密", file=sys.stderr)
        return None

    priv_pem = _find_private_key()
    if not priv_pem:
        print("  [WARN] 未找到 RSA 私钥, 跳过解密", file=sys.stderr)
        return None

    try:
        priv = serialization.load_pem_private_key(priv_pem, password=None)
        key_bytes = key_f.read_bytes()
        aes_key = priv.decrypt(
            key_bytes,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        data = enc.read_bytes()
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
        return json.loads(plain)
    except Exception as e:
        print(f"  [WARN] 解密 {name}: {e}", file=sys.stderr)
        return None


def _is_wildcard_ip(ip: str | None) -> bool:
    if not ip:
        return True
    for prefix in WILDCARD_IPS:
        if ip.startswith(prefix):
            return True
    return False


def _resolve_ip(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        if answers:
            return answers[0].to_text()
    except Exception:
        return None
    return None


def _get_verified_second_level(data: dict, target: str) -> list[str]:
    verified_domains: list[str] = []
    vd = data.get("verified_subdomains", {})
    for subdomain, info in vd.items():
        if not isinstance(info, dict):
            continue
        if info.get("verified") and subdomain.endswith(target):
            dot_count = subdomain.count(".")
            if dot_count == 2:
                verified_domains.append(subdomain)
    return verified_domains


def _brute_level(
    parent_domain: str,
    wordlist: list[str],
    depth_info: dict[str, Any],
    scanned: set[str],
) -> dict[str, str]:
    found: dict[str, str] = {}

    def probe(sub: str) -> tuple[str, str | None]:
        fqdn = f"{sub}.{parent_domain}"
        if fqdn in scanned:
            return fqdn, None
        ip = _resolve_ip(fqdn)
        if ip and not _is_wildcard_ip(ip):
            return fqdn, ip
        return fqdn, None

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(probe, sub): sub for sub in wordlist}
        for fut in as_completed(futs):
            fqdn, ip = fut.result()
            if ip:
                found[fqdn] = ip
                scanned.add(fqdn)

    return found


def main() -> int:
    target = get_target()
    print(f"[deep] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    data = _read_encrypted("verify_subdomains")
    if data is None:
        print("[FATAL] 无法读取 verify_subdomains 数据", file=sys.stderr)
        return 1

    verified_hosts = _get_verified_second_level(data, target)
    print(f"[deep] 已验证二级子域名目标: {len(verified_hosts)}", file=sys.stderr)
    if not verified_hosts:
        print("[WARN] 无已验证的二级子域名, 尝试使用根域名", file=sys.stderr)
        verified_hosts = [target]

    wordlist = load_wordlist("subdomains_large") or load_wordlist("subdomains")
    if not wordlist:
        wordlist = ["www", "mail", "api", "admin", "vpn", "cdn", "blog", "dev", "test"]
    print(f"[deep] 字典: {len(wordlist)} 条", file=sys.stderr)

    all_found: dict[str, str] = {}
    scanned: set[str] = set()

    for host in verified_hosts:
        print(f"\n[deep] 扫描: {host}", file=sys.stderr)

        for depth in range(1, 3):
            if depth == 1:
                targets = [host]
            else:
                targets = [
                    s for s in all_found
                    if s.endswith(host) and s.count(".") == host.count(".") + 1
                ]
                targets = [t for t in targets if t not in scanned]

            if not targets:
                continue

            print(f"  depth={depth}, targets={len(targets)}", file=sys.stderr)

            for parent in targets:
                if parent in scanned:
                    continue
                scanned.add(parent)
                found = _brute_level(parent, wordlist, {}, scanned)
                if found:
                    print(f"    {parent}: +{len(found)}", file=sys.stderr)
                    all_found.update(found)

    elapsed = time.time() - t0
    print(f"\n[deep] 深度子域名总数: {len(all_found)}, {elapsed:.1f}s", file=sys.stderr)

    by_parent: dict[str, list[str]] = {}
    for fqdn in all_found:
        parts = fqdn.split(".")
        if len(parts) >= 3:
            parent = ".".join(parts[1:])
            by_parent.setdefault(parent, []).append(fqdn)

    write_encrypted("deep_subdomains", {
        "target": target,
        "subdomains": sorted(all_found.keys()),
        "resolved": all_found,
        "by_parent": {k: sorted(v) for k, v in by_parent.items()},
        "total": len(all_found),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
