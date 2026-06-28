"""隐藏参数穷举 — GET 参数差异检测."""
from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from _common import get_target, http_get, write_encrypted, load_wordlist


def check_param(base: str, param: str) -> dict | None:
    url_with = f"{base}?{param}=test"
    url_without = base

    r1 = http_get(url_with, timeout=5)
    r2 = http_get(url_without, timeout=5)

    if not r1 or not r2:
        return None

    len1, len2 = len(r1.content), len(r2.content)
    if abs(len1 - len2) > max(len2 * 0.05, 50):
        return {
            "param": param,
            "status_with": r1.status_code,
            "status_without": r2.status_code,
            "size_diff": len1 - len2,
        }
    return None


def main() -> int:
    target = get_target()
    base = f"https://{target}"
    print(f"[param] 目标: {base}", file=sys.stderr)

    wordlist = load_wordlist("params") or [
        "id", "uid", "user_id", "page", "p", "limit", "size",
        "offset", "skip", "sort", "order",
        "filter", "q", "query", "search",
        "lang", "debug", "test", "mode",
        "callback", "format",
        "api_key", "key", "token",
        "redirect", "url", "next",
        "file", "path", "dir",
        "action", "cmd",
        "type", "cat", "tag",
        "v", "version",
    ]
    print(f"[param] 字典: {len(wordlist)}", file=sys.stderr)

    t0 = time.time()
    found: list[dict] = []

    with ThreadPoolExecutor(max_workers=30) as ex:
        futs = {ex.submit(check_param, base, param): param for param in wordlist}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                found.append(r)
                print(f"  [HIT] {r['param']}: diff={r['size_diff']}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[param] {len(found)}/{len(wordlist)}, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("params", {
        "target": target,
        "tested": len(wordlist),
        "found": found,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())