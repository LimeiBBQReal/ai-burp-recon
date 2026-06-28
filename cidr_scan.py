"""C 段存活扫描 + 旁站反查.

功能:
  1. 子域名解析 → 去重 IP
  2. 对每个 IP /24 同网段 ICMP/TCP 探测存活
  3. 存活主机做 HTTP/HTTPS 探活
  4. 证书透明度反查同 IP 旁站

输出 (双层加密):
  out/cidr_data.enc + out/cidr_key.enc
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from _common import get_target, write_encrypted, http_get

RATE_LIMIT = 0.01


def _is_windows() -> bool:
    return sys.platform == "win32"


def _ping(ip: str, timeout: int = 2) -> bool:
    try:
        if _is_windows():
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        return r.returncode == 0
    except Exception:
        return False


def _tcp_alive(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def _http_alive(url: str, timeout: float = 3) -> bool:
    r = http_get(url, timeout=timeout)
    return r is not None


def _cert_alt_names(ip: str) -> list[str]:
    """通过 crt.sh 反查 IP 关联域名 (旁站)."""
    url = f"https://crt.sh/?id={ip}&output=json"
    r = http_get(url, timeout=10)
    if not r or r.status_code != 200:
        url2 = f"https://search.censys.io/certificates?q=parsed.subject.common_name:{ip}"
        return [f"[censys] {url2}"]
    try:
        domains = set()
        for item in r.json():
            name = item.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub:
                    domains.add(sub)
        return sorted(domains)
    except Exception:
        return []


def _resolve_subdomains(target: str) -> tuple[list[dict], set[str]]:
    """读取之前子域名扫描的加密结果. 如果 .data.enc 存在则解密."""
    enc_path = Path(__file__).resolve().parent / "out" / "subdomains.data.enc"
    key_path = Path(__file__).resolve().parent / "out" / "subdomains.key.enc"
    if enc_path.exists() and key_path.exists():
        try:
            import base64
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding, serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

            pub_b64 = os.environ.get("RECON_RSA_PUBLIC", "")
            if not pub_b64:
                return [], set()
            priv_pem = _find_private_key()
            if not priv_pem:
                return [], set()

            priv = serialization.load_pem_private_key(priv_pem, password=None)
            key_enc = key_path.read_bytes()
            aes_key = priv.decrypt(
                key_enc,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            data_enc = enc_path.read_bytes()
            iv = data_enc[:16]
            ct = data_enc[16:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            dec = cipher.decryptor()
            padded = dec.update(ct) + dec.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plain = unpadder.update(padded) + unpadder.finalize()
            obj = json.loads(plain)
            resolved = obj.get("resolved", {})
            ips = set()
            records = []
            for sub, ip in resolved.items():
                ips.add(ip)
                records.append({"subdomain": sub, "ip": ip})
            return records, ips
        except Exception as e:
            print(f"  [WARN] 读取子域名结果: {e}", file=sys.stderr)
    return [], set()


def _find_private_key() -> bytes | None:
    candidates = [
        os.path.expanduser("~/.recon/recon_private.pem"),
        os.path.expanduser("~/.ssh/recon_private.pem"),
        "/root/.recon/recon_private.pem",
    ]
    for c in candidates:
        if os.path.exists(c):
            return Path(c).read_bytes()
    return None


def _scan_c(ip: str, http_ports: list[int]) -> dict:
    """扫描一个 /24 网段."""
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return {str(ip): {"error": f"invalid ip: {ip}"}}

    results: dict[str, dict] = {}
    hosts = [str(h) for h in net.hosts()]

    def probe(h: str) -> tuple[str, dict]:
        ping_ok = _ping(h, timeout=1)
        data: dict[str, Any] = {"ping": ping_ok}
        if ping_ok:
            for port in http_ports:
                if _tcp_alive(h, port):
                    data.setdefault("tcp_open", []).append(port)
                    scheme = "https" if port in (443, 8443) else "http"
                    url = f"{scheme}://{h}:{port}"
                    data.setdefault("http_up", []).append(url)
                    if scheme == "https":
                        data["ssl"] = True
        if RATE_LIMIT:
            time.sleep(RATE_LIMIT)
        return h, data

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = [ex.submit(probe, h) for h in hosts[:20]]
        for fut in as_completed(futs):
            h, data = fut.result()
            if data.get("ping") or data.get("tcp_open"):
                results[h] = data

    return results


def _scan_c_fast(ip: str, http_ports: list[int]) -> dict:
    """快速 C 段 (只扫 .1-.254 的 ping)."""
    results: dict[str, dict] = {}
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return results

    hosts = [str(h) for h in net.hosts()]

    def probe(h: str) -> tuple[str, dict]:
        data: dict[str, Any] = {}
        for port in http_ports:
            if _tcp_alive(h, port, timeout=1):
                data.setdefault("tcp_open", []).append(port)
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{h}:{port}"
                data.setdefault("http_up", []).append(url)
                if scheme == "https":
                    data["ssl"] = True
        if not data:
            if _ping(h, timeout=1):
                data["ping"] = True
        return h, data

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(probe, h): h for h in hosts}
        for fut in as_completed(futs):
            h, data = fut.result()
            if data:
                results[h] = data

    return results


def main() -> int:
    target = get_target()
    print(f"[cidr] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    sub_records, target_ips = _resolve_subdomains(target)
    if target_ips:
        print(f"[cidr] 子域名 IP: {len(target_ips)} 个", file=sys.stderr)
    else:
        try:
            ip = socket.gethostbyname(target)
            target_ips = {ip}
            sub_records = [{"subdomain": target, "ip": ip}]
            print(f"[cidr] 直接解析: {target} -> {ip}", file=sys.stderr)
        except Exception as e:
            print(f"[FATAL] 解析失败: {e}", file=sys.stderr)
            return 1

    http_ports = [80, 443, 8080, 8443, 8000, 8888]
    cidr_results: dict[str, dict] = {}
    side_by_side: dict[str, list[str]] = {}

    for ip in sorted(target_ips):
        print(f"[cidr] 扫描 C 段 {ip}/24 ...", file=sys.stderr)
        cidr_results[ip] = _scan_c_fast(ip, http_ports)

        alive = [h for h, d in cidr_results[ip].items() if d.get("tcp_open") or d.get("http_up")]
        if alive:
            print(f"  {len(alive)} 个存活", file=sys.stderr)

        for h in alive:
            if h in side_by_side:
                continue
            side_domains = _cert_alt_names(h)
            if side_domains:
                side_by_side[h] = side_domains
                print(f"  旁站 {h}: {len(side_domains)} 域名", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[cidr] 完成, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("cidr", {
        "target": target,
        "target_ips": sorted(target_ips),
        "sub_records": sub_records,
        "cidr_scan": cidr_results,
        "side_by_side": side_by_side,
        "alive_total": sum(len(v) for v in cidr_results.values()),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())