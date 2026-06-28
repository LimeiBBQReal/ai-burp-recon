"""URL 全面采集 — Wayback Machine + OTX + HTML 爬取.

功能:
  1. Wayback Machine CDX API: 拉历史 URL (上限 30000)
  2. AlienVault OTX: 关联域名
  3. 主页 HTML 深度爬取 (2 层, a/iframe/src/href)
  4. 合并去重, 按路径/参数/文件后缀分类
  5. 结果可后续喂给 dir_brute / param_brute

输出:
  out/urls.data.enc + out/urls.key.enc
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from _common import get_target, write_encrypted, http_get


CRAWL_DEPTH = 2
MAX_PAGES = 50
LINK_RE = re.compile(r"""<a\s[^>]*href=["']([^"'#]+)["']""", re.I)
IFRAME_RE = re.compile(r"""<iframe\s[^>]*src=["']([^"'#]+)["']""", re.I)
IMG_RE = re.compile(r"""<img\s[^>]*src=["']([^"'#]+)["']""", re.I)
SCRIPT_RE = re.compile(r"""<script\s[^>]*src=["']([^"'#]+)["']""", re.I)


def _is_same_domain(url: str, base_domain: str) -> bool:
    try:
        return base_domain in urlparse(url).netloc
    except Exception:
        return False


def _extract_links(html: str, base_url: str) -> list[str]:
    links = set()
    for pattern in [LINK_RE, IFRAME_RE, IMG_RE, SCRIPT_RE]:
        for m in pattern.finditer(html):
            raw = m.group(1).strip()
            if raw:
                abs_url = urljoin(base_url, raw)
                if abs_url.startswith(("http://", "https://")):
                    links.add(abs_url)
    return sorted(links)


def _crawl(url: str, domain: str, depth: int, visited: set[str], results: list[dict]) -> None:
    if depth > CRAWL_DEPTH or len(visited) > MAX_PAGES:
        return
    if url in visited:
        return
    visited.add(url)

    r = http_get(url, timeout=8)
    if not r:
        results.append({"url": url, "status": 0, "depth": depth, "links": []})
        return

    links = []
    if "text/html" in r.headers.get("content-type", ""):
        links = _extract_links(r.text, url)

    depth_data = {
        "url": url,
        "status": r.status_code,
        "size": len(r.content),
        "content_type": r.headers.get("content-type", ""),
        "depth": depth,
        "links_count": len(links),
    }
    results.append(depth_data)

    for link in links:
        if _is_same_domain(link, domain) and link not in visited:
            _crawl(link, domain, depth + 1, visited, results)


def _wayback_urls(domain: str) -> set[str]:
    urls = set()
    for limit in [5000, 30000]:
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            f"&limit={limit}"
        )
        r = http_get(url, timeout=20)
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


def _otx_domains(domain: str) -> set[str]:
    """AlienVault OTX 关联域名查询."""
    urls = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, timeout=10)
    if not r or r.status_code != 200:
        return urls
    try:
        data = r.json()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "")
            if hostname and hostname.endswith(domain) and hostname != domain:
                urls.add(f"https://{hostname}")
    except Exception:
        pass
    return urls


def main() -> int:
    target = get_target()
    t0 = time.time()
    print(f"[urls] 目标: {target}", file=sys.stderr)

    all_urls: dict[str, list[str]] = {
        "wayback": [],
        "otx": [],
        "crawl": [],
    }

    print("[urls] Wayback Machine 查询...", file=sys.stderr)
    wb = _wayback_urls(target)
    all_urls["wayback"] = sorted(wb)
    print(f"  {len(wb)} URLs", file=sys.stderr)

    print("[urls] OTX 查询...", file=sys.stderr)
    otx = _otx_domains(target)
    all_urls["otx"] = sorted(otx)
    print(f"  {len(otx)} 域名", file=sys.stderr)

    print("[urls] HTML 深度爬取...", file=sys.stderr)
    visited: set[str] = set()
    crawl_results: list[dict] = []
    _crawl(f"https://{target}", target, 0, visited, crawl_results)
    crawl_urls = set()
    for cr in crawl_results:
        crawl_urls.add(cr["url"])
        for link in cr.get("links", []):
            crawl_urls.add(link)
    all_urls["crawl"] = sorted(crawl_urls)
    print(f"  {len(crawl_urls)} URLs (visited {len(visited)})", file=sys.stderr)

    all_combined = sorted(set(wb) | set(otx) | crawl_urls)

    paths: list[str] = []
    params: dict[str, int] = {}
    extensions: dict[str, int] = {}
    subdomains: set[str] = set()

    for u in all_combined:
        parsed = urlparse(u)
        path = parsed.path
        if path and path != "/":
            paths.append(path)

        qs = parse_qs(parsed.query)
        for k in qs:
            params[k] = params.get(k, 0) + 1

        ext = Path(parsed.path).suffix.lower()
        if ext:
            extensions[ext] = extensions.get(ext, 0) + 1

        netloc = parsed.netloc.split(":")[0]
        if netloc.endswith(target) and netloc != target:
            subdomains.add(netloc)

    unique_paths = sorted(set(paths))
    sorted_params = sorted(params.items(), key=lambda x: -x[1])
    sorted_exts = sorted(extensions.items(), key=lambda x: -x[1])

    elapsed = time.time() - t0
    print(f"\n[urls] 完成, 总 {len(all_combined)} URLs, {elapsed:.1f}s", file=sys.stderr)
    print(f"  路径: {len(unique_paths)}, 参数: {len(params)}, 子域名: {len(subdomains)}", file=sys.stderr)

    write_encrypted("urls", {
        "target": target,
        "total_urls": len(all_combined),
        "sources": {k: len(v) for k, v in all_urls.items()},
        "urls": all_combined,
        "unique_paths": unique_paths,
        "unique_subdomains": sorted(subdomains),
        "top_params": dict(sorted_params[:50]),
        "file_extensions": dict(sorted_exts[:30]),
        "crawl_detail": crawl_results,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())