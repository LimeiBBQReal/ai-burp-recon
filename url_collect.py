from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs

from _common import _read_encrypted, write_encrypted, http_get


def _wayback_urls(domain: str) -> set[str]:
    urls = set()
    for limit in (5000, 30000):
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            f"&limit={limit}"
        )
        r = http_get(url, timeout=25)
        if not r or r.status_code != 200:
            continue
        try:
            rows = r.json()
            for row in rows[1:]:
                if row and len(row) > 0:
                    u = row[0].strip()
                    if u and u.startswith(("http://", "https://")):
                        urls.add(u)
            if len(urls) >= limit:
                break
        except Exception:
            pass
    return urls


def _otx_urls(domain: str) -> set[str]:
    urls = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
    r = http_get(url, timeout=15)
    if not r or r.status_code != 200:
        return urls
    try:
        data = r.json()
        for entry in data.get("url_list", []):
            u = entry.get("url", "")
            if u and u.startswith(("http://", "https://")):
                urls.add(u)
    except Exception:
        pass
    return urls


def _crawl_page(url: str, domain: str, depth: int, max_depth: int,
                visited: set[str], collected: set[str]) -> None:
    if depth > max_depth or url in visited:
        return
    visited.add(url)

    r = http_get(url, timeout=10)
    if not r or "text/html" not in r.headers.get("content-type", "").lower():
        return

    html = r.text
    import re
    hrefs = re.findall(r'''\b(?:href|src|action)\s*=\s*(?:"([^"]+)"|'([^']+)')''', html)
    for m in hrefs:
        raw = (m[0] or m[1]).strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        abs_url = urljoin(url, raw)
        if abs_url.startswith(("http://", "https://")) and _same_domain(abs_url, domain):
            collected.add(abs_url)
            if depth < max_depth:
                _crawl_page(abs_url, domain, depth + 1, max_depth, visited, collected)


def _same_domain(url: str, domain: str) -> bool:
    try:
        host = urlparse(url).netloc.split(":")[0]
        return host == domain or host.endswith("." + domain)
    except Exception:
        return False


def main() -> int:
    print("[urls] 读取 verify_subdomains", file=sys.stderr)
    vdata = _read_encrypted("verify_subdomains")
    target = vdata.get("target", "")
    print(f"[urls] 目标: {target}", file=sys.stderr)

    subdomains = list(vdata.get("subdomains", {}).keys())
    if not subdomains:
        subdomains = list(vdata.get("resolved", {}).keys())
    if target not in subdomains:
        subdomains.insert(0, target)

    print(f"[urls] 基础子域名: {len(subdomains)}", file=sys.stderr)

    deep_subs: list[str] = []
    try:
        dd = _read_encrypted("deep_subdomain")
        extra = dd.get("subdomains", [])
        for s in extra:
            if s not in subdomains:
                deep_subs.append(s)
        print(f"[urls] 深度子域名: {len(deep_subs)}", file=sys.stderr)
    except Exception:
        print("[urls] 无 deep_subdomain 数据", file=sys.stderr)

    all_domains = subdomains + deep_subs
    all_urls: set[str] = set()

    t0 = time.time()

    for domain in all_domains:
        print(f"[urls] 采集: {domain}", file=sys.stderr)

        wb = _wayback_urls(domain)
        all_urls.update(wb)
        print(f"  Wayback: {len(wb)}", file=sys.stderr)

        otx = _otx_urls(domain)
        all_urls.update(otx)
        print(f"  OTX: {len(otx)}", file=sys.stderr)

        visited: set[str] = set()
        collected: set[str] = set()
        for proto in ("https", "http"):
            url = f"{proto}://{domain}"
            _crawl_page(url, domain, 0, 2, visited, collected)
        all_urls.update(collected)
        print(f"  Crawl: {len(collected)}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[urls] 总计 {len(all_urls)} URLs, {elapsed:.1f}s", file=sys.stderr)

    by_ext: dict[str, int] = {}
    params: dict[str, int] = {}
    for u in all_urls:
        parsed = urlparse(u)
        ext = parsed.path.split(".")[-1].lower() if "." in parsed.path else ""
        if ext:
            by_ext[ext] = by_ext.get(ext, 0) + 1
        qs = parse_qs(parsed.query)
        for k in qs:
            params[k] = params.get(k, 0) + 1

    write_encrypted("urls", {
        "target": target,
        "total_urls": len(all_urls),
        "subdomains_sourced": len(all_domains),
        "urls": sorted(all_urls),
        "file_extensions": dict(sorted(by_ext.items(), key=lambda x: -x[1])[:30]),
        "top_params": dict(sorted(params.items(), key=lambda x: -x[1])[:50]),
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
