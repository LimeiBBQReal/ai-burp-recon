from __future__ import annotations

import re
import sys
import time
from urllib.parse import urljoin

from _common import _read_encrypted, write_encrypted, http_get

URL_RE = re.compile(r"""(['"`])((?:https?:)?//[^'"`\s]+|/[a-zA-Z0-9_\-./?=&%#+]+)\1""")
REL_PATH_RE = re.compile(r"""(['"`])((?:\.\.?/)[^'"`\s]+)\1""")


def extract_from_js(js_url: str) -> dict:
    r = http_get(js_url, timeout=10)
    if not r or r.status_code != 200:
        return {"url": js_url, "status": r.status_code if r else 0, "extracted": []}

    text = r.text
    urls: set[str] = set()

    for m in URL_RE.findall(text):
        raw = m[1].strip()
        if raw.startswith("//"):
            raw = "https:" + raw
        if raw.startswith(("http://", "https://")):
            urls.add(raw)
        elif raw.startswith("/"):
            abs_url = urljoin(js_url, raw)
            urls.add(abs_url)

    for m in REL_PATH_RE.findall(text):
        raw = m[1].strip()
        abs_url = urljoin(js_url, raw)
        if abs_url.startswith(("http://", "https://")):
            urls.add(abs_url)

    return {
        "url": js_url,
        "status": r.status_code,
        "size": len(text),
        "extracted": sorted(urls),
    }


def main() -> int:
    print("[js] 读取 urls", file=sys.stderr)
    udata = _read_encrypted("urls")
    target = udata.get("target", "")
    print(f"[js] 目标: {target}", file=sys.stderr)

    all_urls = udata.get("urls", [])
    js_urls = sorted(set(
        u for u in all_urls
        if any(u.lower().split("?")[0].endswith(ext) for ext in (".js", ".mjs"))
    ))

    if not js_urls:
        print("[js] 未发现 JS 文件", file=sys.stderr)
        write_encrypted("js_urls", {
            "target": target,
            "files_scanned": 0,
            "unique_urls": [],
            "elapsed_s": 0,
        })
        return 0

    print(f"[js] JS 文件: {len(js_urls)}", file=sys.stderr)

    t0 = time.time()
    results: list[dict] = []

    for js_url in js_urls[:100]:
        r = extract_from_js(js_url)
        results.append(r)
        print(f"  [{r['status']}] {js_url}: {len(r['extracted'])} URLs", file=sys.stderr)

    all_extracted: set[str] = set()
    for r in results:
        all_extracted.update(r["extracted"])

    elapsed = time.time() - t0
    print(f"\n[js] {len(results)} 文件, {len(all_extracted)} 提取 URL, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("js_urls", {
        "target": target,
        "files_scanned": len(results),
        "unique_urls": sorted(all_extracted),
        "details": results,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
