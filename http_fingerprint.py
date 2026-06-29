"""HTTP 指纹采集 — 获取已验证子域名的详细 HTTP 响应信息.

流程:
  1. 读取 Phase 2a 的 verify_subdomains.data.enc
  2. 只取 verified=True 的子域名
  3. 对每个域名执行:
     a) GET / -> status, title, server, content-type, content-length
     b) GET /robots.txt -> content (列出发现的路径)
     c) GET /sitemap.xml -> content
  4. 输出 live_details.json (双层加密)

输出:
  out/live_details.data.enc + out/live_details.key.enc
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from _common import get_target, write_encrypted, http_get

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
except ImportError:
    print("[FATAL] 缺少 cryptography, 请 pip install cryptography", file=sys.stderr)
    sys.exit(1)


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


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""


def _extract_robots_paths(body: str) -> list[str]:
    paths: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                path = parts[1].strip()
                if path and path != "/":
                    paths.append(path)
    return paths


def _get_root(domain: str) -> dict[str, Any]:
    url = f"http://{domain}/"
    r = http_get(url, timeout=10)
    if r is None:
        return {"status": None, "title": "", "server": "", "content_type": "", "content_length": 0}
    return {
        "status": r.status_code,
        "title": _extract_title(r.text) if r.text else "",
        "server": r.headers.get("Server", ""),
        "content_type": r.headers.get("Content-Type", ""),
        "content_length": len(r.content),
    }


def _get_robots(domain: str) -> dict[str, Any]:
    url = f"http://{domain}/robots.txt"
    r = http_get(url, timeout=10)
    if r is None or r.status_code != 200:
        return {"status": r.status_code if r else None, "paths": []}
    body = r.text or ""
    paths = _extract_robots_paths(body)
    return {
        "status": r.status_code,
        "paths": paths,
        "body_preview": body[:500],
    }


def _get_sitemap(domain: str) -> dict[str, Any]:
    url = f"http://{domain}/sitemap.xml"
    r = http_get(url, timeout=10)
    if r is None or r.status_code != 200:
        return {"status": r.status_code if r else None, "content": ""}
    body = r.text or ""
    return {
        "status": r.status_code,
        "content_preview": body[:500],
    }


def _fingerprint_domain(domain: str) -> tuple[str, dict[str, Any]]:
    root = _get_root(domain)
    robots = _get_robots(domain)
    sitemap = _get_sitemap(domain)

    details = {
        "root": root,
        "robots_txt": robots,
        "sitemap_xml": sitemap,
    }
    return domain, details


def _get_verified_domains(data: dict) -> list[str]:
    vd = data.get("verified_subdomains", {})
    if isinstance(vd, dict):
        return [sub for sub, info in vd.items() if isinstance(info, dict) and info.get("verified")]
    return []


def main() -> int:
    target = get_target()
    print(f"[fingerprint] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    data = _read_encrypted("verify_subdomains")
    if data is None:
        print("[FATAL] 无法读取 verify_subdomains 数据", file=sys.stderr)
        return 1

    domains = _get_verified_domains(data)
    print(f"[fingerprint] 已验证域名: {len(domains)}", file=sys.stderr)

    if not domains:
        print("[WARN] 无已验证域名, 输出空结果", file=sys.stderr)
        write_encrypted("live_details", {
            "target": target,
            "live_details": {},
            "total": 0,
            "elapsed_s": 0,
        })
        return 0

    results: dict[str, dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(_fingerprint_domain, domain): domain for domain in domains}
        for fut in as_completed(futs):
            domain, details = fut.result()
            results[domain] = details
            root = details["root"]
            print(
                f"  [{root.get('status', '?')}] {domain} "
                f"| {root.get('title', '')[:50]} "
                f"| {root.get('server', '')[:30]}"
                f"| robots:{details['robots_txt'].get('status', '?')}"
                f"| sitemap:{details['sitemap_xml'].get('status', '?')}",
                file=sys.stderr,
            )

    elapsed = time.time() - t0
    print(f"\n[fingerprint] 完成: {len(results)} 域名, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("live_details", {
        "target": target,
        "live_details": results,
        "total": len(results),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
