from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from _common import _read_encrypted, write_encrypted, http_get


def grab_banner(url: str, timeout: float = 8) -> dict:
    result = {"url": url, "status": 0, "headers": {}, "body_size": 0, "error": None}
    try:
        r = http_get(url, timeout=timeout, allow_redirects=True)
        if not r:
            result["error"] = "connection failed"
            return result
        result["status"] = r.status_code
        result["headers"] = dict(r.headers)
        body = r.text[:2000]
        result["body_size"] = len(r.content)
        result["body_preview"] = body[:500]
        result["server"] = r.headers.get("Server", "")
        result["content_type"] = r.headers.get("Content-Type", "")
        result["title"] = extract_title(body)
    except Exception as e:
        result["error"] = str(e)
    return result


def extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:200] if m else ""


def main() -> int:
    print("[banner] 读取 http_fingerprint", file=sys.stderr)
    fp = _read_encrypted("http_fingerprint")
    target = fp.get("target", "")
    print(f"[banner] 目标: {target}", file=sys.stderr)

    live_urls: list[str] = []
    for entry in fp.get("results", []):
        url = entry.get("url", "")
        if url:
            live_urls.append(url)

    print(f"[banner] 待抓取 URL: {len(live_urls)}", file=sys.stderr)

    t0 = time.time()
    banners: list[dict] = []

    with ThreadPoolExecutor(max_workers=15) as ex:
        futs = {ex.submit(grab_banner, url): url for url in live_urls}
        for fut in as_completed(futs):
            r = fut.result()
            banners.append(r)
            if r.get("status"):
                print(f"  [{r['status']}] {r['url']} | {r.get('server','')[:60]}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[banner] {len(banners)} 完成, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("banners", {
        "target": target,
        "total": len(banners),
        "results": banners,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
