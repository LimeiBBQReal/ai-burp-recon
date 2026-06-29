"""Authoritative DNS records only (no brute force).

Queries A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, CAA records
using system resolver (no dictionary/brute force).

Output:
  out/dns_authoritative.data.enc + .key.enc

Wildcard DNS detection: 198.18.x.x/15 ranges are filtered out.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import dns.resolver
import dns.rdtypes
import dns.rdatatype

from _common import get_target, write_encrypted

WILDCARD_NETWORKS = [ipaddress.ip_network("198.18.0.0/15")]

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV", "CAA"]


def _is_wildcard(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in WILDCARD_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False


def _query_records(domain: str, rtype: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
        for rr in answers:
            entry: dict[str, Any] = {"type": rtype}
            if rtype == "A":
                val = str(rr.address)
                if _is_wildcard(val):
                    entry["value"] = val
                    entry["wildcard"] = True
                else:
                    entry["value"] = val
                    entry["wildcard"] = False
            elif rtype == "AAAA":
                val = str(rr.address)
                entry["value"] = val
            elif rtype == "MX":
                entry["value"] = str(rr.exchange).rstrip(".")
                entry["preference"] = rr.preference
            elif rtype == "TXT":
                entry["value"] = "".join(part.decode() if isinstance(part, bytes) else part for part in rr.strings)
            elif rtype == "NS":
                entry["value"] = str(rr.target).rstrip(".")
            elif rtype == "SOA":
                entry["mname"] = str(rr.mname).rstrip(".")
                entry["rname"] = str(rr.rname).rstrip(".")
                entry["serial"] = rr.serial
            elif rtype == "CNAME":
                entry["value"] = str(rr.target).rstrip(".")
            elif rtype == "SRV":
                entry["value"] = str(rr.target).rstrip(".")
                entry["port"] = rr.port
                entry["priority"] = rr.priority
                entry["weight"] = rr.weight
            elif rtype == "CAA":
                entry["value"] = rr.value.decode() if isinstance(rr.value, bytes) else rr.value
                entry["tag"] = rr.tag.decode() if isinstance(rr.tag, bytes) else rr.tag
                entry["flags"] = rr.flags
            results.append(entry)
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except Exception as e:
        print(f"  [ERR] {rtype} {domain}: {e}", file=sys.stderr)
    return results


def _resolve_mx_ips(mx_hostname: str) -> list[str]:
    ips: list[str] = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(mx_hostname, "A")
        for rr in answers:
            ip_str = str(rr.address)
            if not _is_wildcard(ip_str):
                ips.append(ip_str)
    except Exception:
        pass
    return ips


def main() -> int:
    target = get_target()
    print(f"[dns_auth] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    all_records: dict[str, list[dict[str, Any]]] = {}
    target_ips: set[str] = set()
    mx_servers: list[dict[str, Any]] = []

    def query_all(domain: str) -> None:
        records: list[dict[str, Any]] = []
        for rtype in RECORD_TYPES:
            recs = _query_records(domain, rtype)
            records.extend(recs)
            for rec in recs:
                if rtype == "A" and not rec.get("wildcard"):
                    target_ips.add(rec["value"])
                if rtype == "MX":
                    mx_host = rec["value"]
                    mx_ips = _resolve_mx_ips(mx_host)
                    mx_servers.append({
                        "hostname": mx_host,
                        "preference": rec["preference"],
                        "ips": mx_ips,
                    })
                    for ip in mx_ips:
                        target_ips.add(ip)
        all_records[domain] = records

    query_all(target)

    for rec in all_records.get(target, []):
        if rec["type"] == "CNAME":
            cname_target = rec["value"]
            query_all(cname_target)

    elapsed = time.time() - t0
    print(f"\n[dns_auth] 完成, {elapsed:.1f}s", file=sys.stderr)
    print(f"  记录总数: {sum(len(v) for v in all_records.values())}", file=sys.stderr)
    print(f"  目标 IPs: {len(target_ips)}", file=sys.stderr)
    print(f"  MX 服务器: {len(mx_servers)}", file=sys.stderr)

    write_encrypted("dns_authoritative", {
        "target": target,
        "records": all_records,
        "target_ips": sorted(target_ips, key=lambda x: tuple(int(o) for o in x.split("."))),
        "mx_servers": mx_servers,
        "record_types_queried": RECORD_TYPES,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
