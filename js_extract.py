"""JS/CSS URL 提取 + 解析."""
from __future__ import annotations

import sys
import time
import re
from urllib.parse import urljoin

from _common import get_target, http_get, write_encrypted

URL_RE = re.compile(r"""(['"`])((?:https?:)?//[^'"`\s]+|/[a-zA-Z0-9_\-./?=&%]+)\1""")


def extract_from_url(url: str) -> dict:
    r = http_get(url)
    if not r or r.status_code != 200:
        return {"url": url, "status": r.status_code if r else 0, "urls": []}

    text = r.text
    urls = list(set(m[1] for m in URL_RE.findall(text)))

    return {
        "url": url,
        "status": r.status_code,
        "size": len(text),
        "urls": urls,
    }


def main() -> int:
    target = get_target()
    print(f"[js] 目标: {target}", file=sys.stderr)

    base = f"https://{target}"
    home = http_get(base)
    if not home:
        print(f"[FATAL] 无法访问 {base}", file=sys.stderr)
        return 1

    js_css_links = re.findall(r"""<script[^>]+src=['"]([^'"]+)['"]""", home.text)
    js_css_links += re.findall(r"""<link[^>]+href=['"]([^'"]+\.css)['"]""", home.text)

    abs_urls = [urljoin(base, u) for u in js_css_links]
    print(f"[js] 发现 {len(abs_urls)} 个 JS/CSS", file=sys.stderr)

    t0 = time.time()
    all_results = []
    for url in abs_urls[:50]:
        result = extract_from_url(url)
        all_results.append(result)
        print(f"  [{result['status']}] {url}: {len(result['urls'])} URLs", file=sys.stderr)

    all_urls = set()
    for r in all_results:
        all_urls.update(r["urls"])

    elapsed = time.time() - t0
    print(f"\n[js] {len(all_urls)} URLs, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("js_urls", {
        "target": target,
        "files_scanned": len(all_results),
        "unique_urls": sorted(all_urls),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())