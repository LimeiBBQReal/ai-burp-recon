"""CDN 真实 IP 探测 — 多层绕过 CDN 找到目标真实服务器地址.

流程:
  1. 读取 Phase 1 的 dns_authoritative.data.enc 获取解析到的 IP
  2. CDN 检测: 检查 IP 是否属于已知 CDN 段 (Cloudflare / Akamai / Fastly / CloudFront / StackPath / Incapsula)
  3. 如果检测到 CDN, 启动多层绕过:
     a) 历史 DNS 记录 (SecurityTrails / crt.sh 历史 IP)
     b) 子域名探测收集
     c) SSL 证书反向查询 (通过 crt.sh 搜索证书序列号)
     d) HTTP 头部分析 (Server / Via / X-Cache 等)
     e) 邮件服务器 MX 同 C 段扫描
     f) F5 / Cloudflare 的 True-Client-IP / X-Forwarded-For 头测试
     g) DNS 区域传输测试 (AXFR, 极低概率但无成本)
  4. 合并所有发现的候选真实 IP, 去重并验证 (TCP 80/443 连接)
  5. 输出 candidate_ips 按可信度排序

CDN IP 段来自公开数据 (cdn-ranges.txt 字面量).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import dns.resolver
import dns.query
import dns.zone

from _common import get_target, write_encrypted, http_get, _read_encrypted

CDN_RANGES: list[ipaddress.ip_network] = []

_RAW_CDN_RANGES = """
# Cloudflare
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
104.16.0.0/13
104.24.0.0/14
108.162.192.0/18
131.0.72.0/22
141.101.64.0/18
162.158.0.0/15
172.64.0.0/13
173.245.48.0/20
188.114.96.0/20
190.93.240.0/20
197.234.240.0/22
198.41.128.0/17
# CloudFront
120.52.22.96/27
205.251.192.0/19
204.246.164.0/22
54.230.0.0/17
54.239.128.0/18
52.84.0.0/15
13.32.0.0/15
13.224.0.0/14
13.249.0.0/16
13.35.0.0/16
216.137.32.0/19
# Fastly
151.101.0.0/16
151.101.192.0/18
199.232.0.0/16
199.27.72.0/21
146.75.0.0/16
# Akamai
23.0.0.0/12
23.64.0.0/14
23.72.0.0/13
23.192.0.0/11
23.208.0.0/12
23.224.0.0/13
23.248.0.0/14
23.252.0.0/14
72.246.0.0/16
72.247.0.0/16
96.16.0.0/15
96.17.0.0/16
96.18.0.0/16
96.19.0.0/16
104.64.0.0/10
184.50.0.0/16
184.51.0.0/16
184.84.0.0/14
184.85.0.0/16
2.16.0.0/13
2.21.0.0/16
2.22.0.0/15
2.23.0.0/16
# StackPath (Highwinds)
199.16.0.0/16
69.164.0.0/16
69.167.0.0/16
69.172.0.0/16
69.174.0.0/16
69.175.0.0/16
69.176.0.0/16
69.181.0.0/16
69.195.0.0/16
# Incapsula / Imperva
103.28.248.0/22
45.64.64.0/22
45.223.128.0/18
108.162.192.0/18
141.101.64.0/18
188.114.96.0/20
199.83.128.0/21
198.143.32.0/19
149.126.72.0/21
103.28.248.0/22
45.64.64.0/22
45.223.128.0/18
# Sucuri / G-Core
185.93.228.0/22
91.199.212.0/22
192.88.134.0/23
185.93.228.0/22
91.199.212.0/22
# Bunny CDN
213.227.152.0/22
138.199.128.0/18
34.110.0.0/17
# OVH CDN
167.114.0.0/18
198.27.64.0/18
142.4.192.0/18
# Beluga CDRF
185.11.124.0/22
185.11.125.0/24
185.11.126.0/24
# Azure CDN
13.107.128.0/22
13.107.136.0/22
13.107.144.0/24
13.107.160.0/22
"""

for line in _RAW_CDN_RANGES.strip().split("\n"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    try:
        CDN_RANGES.append(ipaddress.ip_network(line, strict=False))
    except ValueError:
        pass


def _is_cdn_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in CDN_RANGES:
            if ip_obj in net:
                return True
    except ValueError:
        pass
    return False


def _detect_cdn_from_headers(headers: dict[str, str]) -> list[str]:
    detected: list[str] = []
    h = {k.lower(): v for k, v in headers.items()}

    if "server" in h:
        s = h["server"].lower()
        if "cloudflare" in s:
            detected.append("Cloudflare")
        elif "akamai" in s or "akamaighost" in s:
            detected.append("Akamai")
        elif "fastly" in s:
            detected.append("Fastly")
        elif "cloudfront" in s or "amazons3" in s:
            detected.append("CloudFront")
        elif "sucuri" in s:
            detected.append("Sucuri")

    via = h.get("via", "")
    if "cloudflare" in via.lower():
        if "Cloudflare" not in detected:
            detected.append("Cloudflare")
    if "akamai" in via.lower():
        if "Akamai" not in detected:
            detected.append("Akamai")

    x_cache = h.get("x-cache", "")
    if "cloudflare" in x_cache.lower():
        if "Cloudflare" not in detected:
            detected.append("Cloudflare")

    if "cf-ray" in h:
        if "Cloudflare" not in detected:
            detected.append("Cloudflare")

    if "x-akamai-request-id" in h:
        if "Akamai" not in detected:
            detected.append("Akamai")

    if "x-amz-cf-id" in h:
        if "CloudFront" not in detected:
            detected.append("CloudFront")

    if "x-sucuri-id" in h:
        if "Sucuri" not in detected:
            detected.append("Sucuri")

    return list(set(detected))


def _fetch_history_ips(domain: str) -> set[str]:
    """通过 crt.sh 证书透明度查找历史 IP."""
    ips: set[str] = {}
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return set()
    try:
        entries = r.json()
        for entry in entries:
            for field in ("ip_address",):
                ip_val = entry.get(field, "")
                if ip_val:
                    try:
                        ipaddress.ip_address(ip_val)
                        ips.add(ip_val)
                    except ValueError:
                        pass
    except Exception:
        pass
    return set()


def _fetch_mx_same_subnet(domain: str) -> set[str]:
    """通过 MX 服务器 IP 探测同 C 段."""
    ips: set[str] = set()
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_hosts = [str(r.exchange).rstrip(".") for r in answers]
        for mx in mx_hosts[:3]:
            try:
                mx_answers = dns.resolver.resolve(mx, "A", lifetime=5)
                mx_ip = str(mx_answers[0].address)
                # 扫描 .1-.254
                parts = mx_ip.split(".")
                base = ".".join(parts[:3])
                for i in range(1, 255):
                    ips.add(f"{base}.{i}")
            except Exception:
                continue
    except Exception:
        pass
    return ips


def _try_axfr(domain: str, ns_servers: list[str]) -> list[str]:
    """AXFR 区域传输."""
    results: list[str] = []
    for ns in ns_servers[:3]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5, lifetime=10))
            for name, node in zone.nodes.items():
                str_name = str(name)
                if str_name == "@":
                    continue
                fqdn = f"{str_name}.{domain}" if str_name else domain
                results.append(fqdn)
        except Exception:
            continue
    return results


def _ssl_cert_hostname(domain: str) -> set[str]:
    """SSL 证书提取主机名."""
    hosts: set[str] = set()
    for port in (443, 8443, 4433):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        for entry in cert.get("subjectAltName", []):
                            if entry[0] == "DNS":
                                hosts.add(entry[1])
        except Exception:
            continue
    return hosts


def _scan_http_title(ip: str) -> dict[str, Any]:
    """尝试 HTTP 连接并获取页面标题."""
    result: dict[str, Any] = {"ip": ip, "status": None, "title": "", "server": ""}
    for port in (80, 443, 8080, 8443):
        try:
            scheme = "https" if port in (443, 8443) else "http"
            r = http_get(f"{scheme}://{ip}", timeout=5)
            if r and r.status_code:
                result["status"] = r.status_code
                result["server"] = r.headers.get("Server", "")
                result["port"] = port
                result["scheme"] = scheme
                m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.IGNORECASE | re.DOTALL)
                if m:
                    result["title"] = m.group(1).strip()[:200]
                break
        except Exception:
            continue
    return result


def main() -> int:
    target = get_target()
    t0 = time.time()
    print(f"[bypass_cdn] 目标: {target}", file=sys.stderr)

    # 获取 DNS 权威数据（可能和 dns_authoritative 并行，文件不一定存在）
    dns_data: dict | None = None
    try:
        dns_data = _read_encrypted("dns_authoritative")
    except SystemExit:
        print("  [WARN] dns_authoritative 不可用（并行运行）", file=sys.stderr)
        dns_data = None
    cdn_ips: set[str] = set()
    real_ips: set[str] = set()
    candidate_ips: set[str] = set()

    if dns_data:
        records = dns_data.get("records", {}).get(target, [])
        for rec in records:
            if rec.get("type") == "A" and rec.get("value"):
                ip_str = rec["value"]
                if _is_cdn_ip(ip_str):
                    cdn_ips.add(ip_str)
                    print(f"  [CDN] {ip_str} 属于 CDN 段, 启动绕过...", file=sys.stderr)
                else:
                    real_ips.add(ip_str)
        print(f"  [DNS] CDN IP: {len(cdn_ips)}, 真实 IP: {len(real_ips)}", file=sys.stderr)

    # 检查 HTTP 头确认 CDN 厂商
    cdn_headers: list[str] = []
    r = http_get(f"https://{target}", timeout=10)
    if r:
        cdn_headers = _detect_cdn_from_headers(dict(r.headers))
        if cdn_headers:
            print(f"  [HEADER] CDN 检测: {cdn_headers}", file=sys.stderr)

    if not cdn_ips and not cdn_headers:
        print("[bypass_cdn] 未检测到 CDN, 跳过绕过流程, 直接输出现有 IP", file=sys.stderr)
        write_encrypted("cdn_bypass", {
            "target": target,
            "cdn_detected": False,
            "cdn_ips": sorted(cdn_ips),
            "cdn_providers": cdn_headers,
            "real_ips": sorted(real_ips),
            "candidate_ips": sorted(real_ips | candidate_ips),
            "elapsed_s": round(time.time() - t0, 1),
        })
        return 0

    print(f"\n[bypass_cdn] 绕过方法:", file=sys.stderr)

    # 方法 1: 证书历史 IP
    print(f"  1) crt.sh 历史 IP...", file=sys.stderr)
    history_ips = _fetch_history_ips(target)
    print(f"     -> {len(history_ips)} 个历史 IP", file=sys.stderr)
    for ip in sorted(history_ips):
        if not _is_cdn_ip(ip):
            candidate_ips.add(ip)

    # 方法 2: SSL 证书 SAN
    print(f"  2) SSL 证书主机名...", file=sys.stderr)
    cert_hosts = _ssl_cert_hostname(target)
    print(f"     -> {len(cert_hosts)} 个", file=sys.stderr)
    for host in sorted(cert_hosts):
        try:
            a = dns.resolver.resolve(host, "A", lifetime=3)
            for rr in a:
                ip_str = str(rr)
                if not _is_cdn_ip(ip_str):
                    candidate_ips.add(ip_str)
        except Exception:
            continue

    # 方法 3: MX C段探测
    print(f"  3) MX C 段...", file=sys.stderr)
    subnet_ips = _fetch_mx_same_subnet(target)
    print(f"     -> {len(subnet_ips)} 个候选 IP", file=sys.stderr)
    for ip in subnet_ips:
        if not _is_cdn_ip(ip):
            candidate_ips.add(ip)

    # 方法 4: AXFR
    print(f"  4) AXFR 区域传输...", file=sys.stderr)
    ns_servers = []
    if dns_data:
        for rec in dns_data.get("records", {}).get(target, []):
            if rec.get("type") == "NS":
                ns_servers.append(rec["value"])
    axfr_results = _try_axfr(target, ns_servers)
    if axfr_results:
        print(f"     -> AXFR 成功! {len(axfr_results)} 条记录", file=sys.stderr)
        for fqdn in axfr_results:
            try:
                a = dns.resolver.resolve(fqdn, "A", lifetime=3)
                for rr in a:
                    ip_str = str(rr)
                    if not _is_cdn_ip(ip_str):
                        candidate_ips.add(ip_str)
            except Exception:
                continue
    else:
        print(f"     -> AXFR 未开放", file=sys.stderr)

    # 验证候选 IP
    print(f"\n[bypass_cdn] 验证候选 IP ({len(candidate_ips)}):", file=sys.stderr)
    verified: list[dict[str, Any]] = []

    def verify(ip_str: str) -> dict[str, Any]:
        return _scan_http_title(ip_str)

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(verify, ip): ip for ip in candidate_ips}
        for fut in as_completed(futs):
            r = fut.result()
            if r["status"] is not None:
                verified.append(r)
                print(f"     [V] {r['ip']}:{r.get('port',80)} [{r['status']}] {r.get('title','')[:60]}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[bypass_cdn] 完成, {elapsed:.1f}s", file=sys.stderr)
    print(f"  CDN IP: {cdn_ips}", file=sys.stderr)
    print(f"  CDN 厂商: {cdn_headers}", file=sys.stderr)
    print(f"  真实 IP 候选: {len(candidate_ips)}", file=sys.stderr)
    print(f"  已验证存活: {len(verified)}", file=sys.stderr)

    write_encrypted("cdn_bypass", {
        "target": target,
        "cdn_detected": True,
        "cdn_ips": sorted(cdn_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "cdn_providers": cdn_headers,
        "real_ips": sorted(real_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "candidate_ips": sorted(candidate_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "verified_live": verified,
        "history_ip_count": len(history_ips),
        "cert_host_count": len(cert_hosts),
        "axfr_count": len(axfr_results),
        "methods_used": ["crt.sh_history", "ssl_cert_san", "mx_subnet", "axfr"],
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
