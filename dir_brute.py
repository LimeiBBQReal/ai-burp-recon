"""目录/文件穷举."""
from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from _common import get_target, http_get, write_encrypted, load_wordlist


def check_path(base: str, path: str) -> dict | None:
    url = f"{base.rstrip('/')}/{path}"
    r = http_get(url, timeout=5)
    if not r:
        return None
    if r.status_code in (200, 204, 301, 302, 401, 403, 500, 502, 503):
        return {
            "path": path,
            "url": url,
            "status": r.status_code,
            "size": len(r.content),
        }
    return None


def main() -> int:
    target = get_target()
    base = f"https://{target}"
    print(f"[dir] 目标: {base}", file=sys.stderr)

    small_list = load_wordlist("dirs")
    large_list = load_wordlist("dirs_large")

    if large_list:
        wordlist = large_list
        print(f"[+] 使用大字典: {len(large_list)} 条 (注意: large 模式不设硬编码回退)", file=sys.stderr)
    else:
        wordlist = small_list or [
            "admin", "login",
        ]
    print(f"[dir] 字典: {len(wordlist)}", file=sys.stderr)

    t0 = time.time()
    found: list[dict] = []

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(check_path, base, path): path for path in wordlist}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                found.append(r)
                print(f"  [{r['status']}] {r['path']}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[dir] {len(found)}/{len(wordlist)}, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("dirs", {
        "target": target,
        "tested": len(wordlist),
        "found": found,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())