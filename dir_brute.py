from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from _common import _read_encrypted, write_encrypted, http_get, load_wordlist


def check_path(base: str, path: str) -> dict | None:
    base = base.rstrip("/")
    url = f"{base}/{path}"
    r = http_get(url, timeout=5)
    if not r:
        return None
    if r.status_code in (200, 204, 301, 302, 307, 308, 401, 403, 500, 502, 503):
        return {
            "path": path,
            "url": url,
            "status": r.status_code,
            "size": len(r.content),
        }
    return None


def main() -> int:
    print("[dir] 读取 http_fingerprint", file=sys.stderr)
    fp = _read_encrypted("http_fingerprint")
    target = fp.get("target", "")
    print(f"[dir] 目标: {target}", file=sys.stderr)

    live_urls: list[str] = []
    for entry in fp.get("results", []):
        url = entry.get("url", "")
        if url:
            live_urls.append(url)

    wordlist = load_wordlist("dirs_large")
    if not wordlist:
        wordlist = load_wordlist("dirs")
    if not wordlist:
        print("[FATAL] 未找到 dirs_large 或 dirs wordlist", file=sys.stderr)
        return 1

    print(f"[dir] 字典: {len(wordlist)}, 目标 URL: {len(live_urls)}", file=sys.stderr)

    t0 = time.time()
    all_found: dict[str, list[dict]] = {}

    for base in live_urls:
        found: list[dict] = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {ex.submit(check_path, base, path): path for path in wordlist}
            for fut in as_completed(futs):
                r = fut.result()
                if r:
                    found.append(r)
                    print(f"  [{r['status']}] {r['url']}", file=sys.stderr)
        if found:
            all_found[base] = found
            print(f"  {base}: {len(found)} 发现", file=sys.stderr)

    elapsed = time.time() - t0
    total_found = sum(len(v) for v in all_found.values())
    print(f"\n[dir] 总计 {total_found} 发现, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("dirs", {
        "target": target,
        "sources": live_urls,
        "wordlist_size": len(wordlist),
        "total_found": total_found,
        "results": all_found,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
