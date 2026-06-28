"""DNS 记录枚举 — A/AAAA/MX/TXT/NS/CNAME/SOA/SRV/CAA."""
from __future__ import annotations

import sys
import time

import dns.resolver

from _common import get_target, write_encrypted

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "CAA"]


def query_record(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def main() -> int:
    target = get_target()
    print(f"[dns] 目标: {target}", file=sys.stderr)
    t0 = time.time()

    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        results = query_record(target, rtype)
        if results:
            records[rtype] = results
            print(f"  [{rtype}] {len(results)} 条", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[dns] 完成, 耗时 {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("dns", {
        "target": target,
        "records": records,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())