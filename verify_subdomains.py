"""子域名存活验证 — DNS 解析 + HTTP 探活 + 通配符检测.

流程:
  1. 读取 Phase 1 的 passive_sources.data.enc
  2. 发送随机不存在的子域名, 捕获通配符指纹
  3. 对每个候选子域名:
     a) DNS A 记录查询, 过滤通配符 IP (198.18.x.x, 0.0.0.0, 空)
     b) HTTP HEAD 请求验证真实 Web 服务器
     c) 与通配符指纹比对, 排除通配符响应
  4. 输出 verified_subdomains.json (双层加密)

输出:
  out/verify_subdomains.data.enc + out/verify_subdomains.key.enc
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

from _common import get_target, write_encrypted, http_get

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


def _resolve_a(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        if answers:
            return answers[0].to_text()
    except Exception:
        return None
    return None


def _head_request(domain: str) -> dict[str, Any]:
    url = f"http://{domain}/"
    r = http_get(url, timeout=8, method="HEAD")
    if r is None:
        return {"status": None, "title": "", "server": ""}
    return {
        "status": r.status_code,
        "title": _extract_title(r.text) if r.text else "",
        "server": r.headers.get("Server", ""),
        "body_preview": r.text[:200] if r.text else "",
    }


def _get_request(domain: str) -> dict[str, Any]:
    url = f"http://{domain}/"
    r = http_get(url, timeout=8)
    if r is None:
        return {"status": None, "title": "", "server": "", "body": ""}
    return {
        "status": r.status_code,
        "title": _extract_title(r.text) if r.text else "",
        "server": r.headers.get("Server", ""),
        "body": r.text or "",
    }


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""


def _get_wildcard_fingerprint(domain: str) -> dict[str, Any] | None:
    import uuid
    random_sub = str(uuid.uuid4()).replace("-", "")[:12]
    test_fqdn = f"{random_sub}.{domain}"
    ip = _resolve_a(test_fqdn)
    if not ip:
        return None
    resp = _get_request(test_fqdn)
    return {"ip": ip, "body": resp.get("body", ""), "title": resp.get("title", "")}


def _is_wildcard_response(wc: dict[str, Any] | None, ip: str | None, resp: dict[str, Any]) -> bool:
    if _is_wildcard_ip(ip):
        return True
    if wc is None:
        return False
    wc_body = wc.get("body", "")
    if not wc_body:
        return False
    body = resp.get("body", "")
    if len(body) > 50 and body[:100] == wc_body[:100]:
        return True
    return False


def _verify_candidate(
    subdomain: str,
    wildcard_fp: dict[str, Any] | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "subdomain": subdomain,
        "verified": False,
        "ip": None,
        "title": "",
        "server": "",
        "status": None,
    }

    ip = _resolve_a(subdomain)
    if _is_wildcard_ip(ip):
        result["ip"] = ip
        return result

    result["ip"] = ip

    resp = _get_request(subdomain)
    if resp["status"] is None:
        return result

    if _is_wildcard_response(wildcard_fp, ip, resp):
        return result

    result["verified"] = True
    result["title"] = resp.get("title", "")
    result["server"] = resp.get("server", "")
    result["status"] = resp["status"]
    return result


def main() -> int:
    target = get_target()
    print(f"[verify] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    data = _read_encrypted("passive_sources")
    if data is None:
        print("[FATAL] 无法读取 passive_sources 数据", file=sys.stderr)
        return 1

    candidates: list[str] = data.get("unique_subdomains", []) or data.get("subdomains", [])
    if not candidates:
        print("[WARN] 没有候选子域名", file=sys.stderr)
        write_encrypted("verify_subdomains", {"target": target, "verified": [], "total": 0, "elapsed_s": 0})
        return 0

    print(f"[verify] 候选子域名: {len(candidates)}", file=sys.stderr)

    print("[verify] 获取通配符指纹...", file=sys.stderr)
    wildcard_fp = _get_wildcard_fingerprint(target)
    if wildcard_fp:
        print(f"  [WC] 通配符 IP: {wildcard_fp['ip']}, title: {wildcard_fp['title'][:60]}", file=sys.stderr)
    else:
        print("  [WC] 未检测到通配符", file=sys.stderr)

    verified: list[dict[str, Any]] = []

    def verify_one(sub: str) -> dict[str, Any]:
        fqdn = f"{sub}.{target}" if not sub.endswith(target) else sub
        return _verify_candidate(fqdn, wildcard_fp)

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(verify_one, sub): sub for sub in candidates}
        for fut in as_completed(futs):
            r = fut.result()
            verified.append(r)
            sub = r["subdomain"]
            if r["verified"]:
                print(f"  [V] {sub} -> {r['ip']} [{r['status']}] {r['title'][:60]}", file=sys.stderr)
            else:
                print(f"  [X] {sub} -> {r.get('ip', 'N/A')}", file=sys.stderr)

    elapsed = time.time() - t0
    verified_count = sum(1 for v in verified if v["verified"])
    print(f"\n[verify] 已验证: {verified_count}/{len(verified)}, {elapsed:.1f}s", file=sys.stderr)

    by_domain: dict[str, dict[str, Any]] = {}
    for v in verified:
        by_domain[v["subdomain"]] = {
            "verified": v["verified"],
            "ip": v["ip"],
            "title": v["title"],
            "server": v["server"],
            "status": v["status"],
        }

    write_encrypted("verify_subdomains", {
        "target": target,
        "verified_subdomains": by_domain,
        "total": len(verified),
        "verified_count": verified_count,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
