"""URL 全面采集 — Wayback Machine + OTX + 深度爬取 (HTML/JS/CSS/JSON/XML).

功能:
  1. Wayback Machine CDX API: 拉历史 URL (上限 30000)
  2. AlienVault OTX: 关联域名
  3. 主页 HTML 深度爬取 (2 层)
  4. 对每个静态资源 (.js/.css/.json/.xml/.txt/.map 等) 都拉取源码并提取 URL
  5. 提取覆盖:
       HTML: a/href, iframe/src, img/src, script/src, link/href, form/action,
             source/src, embed/src, video/audio, object/data, area/href, use/href,
             meta[content|url|property=og:*]
       CSS:  @import "x", url("x"), url(x), @font-face src: url(...)
       JS:   "https?://...", 'https?://...', `https?://...`,
             import "...", import('...'), require("..."), fetch("..."),
             XMLHttpRequest.open("..."), new URL("..."), axios.{get,post,...}("..."),
             location.href = "..."
       JSON: 任意 string 字段里的 http(s)://
       XML:  <?xml-stylesheet href="..."?> 之类
  6. 合并去重, 按路径/参数/文件后缀分类

输出:
  out/urls.data.enc + out/urls.key.enc
"""
from __future__ import annotations

import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from _common import get_target, write_encrypted, http_get


CRAWL_DEPTH = 2
MAX_PAGES = 80
MAX_STATIC_BYTES = 1024 * 512

HTML_TAGS = [
    ("a", "href"),
    ("link", "href"),
    ("script", "src"),
    ("iframe", "src"),
    ("frame", "src"),
    ("img", "src"),
    ("source", "src"),
    ("track", "src"),
    ("embed", "src"),
    ("video", "src"),
    ("audio", "src"),
    ("object", "data"),
    ("area", "href"),
    ("use", "href"),
    ("form", "action"),
    ("input", "src"),
    ("html", "manifest"),
    ("base", "href"),
]

HTML_TAG_ATTR_RE = re.compile(
    r"""<\s*([a-zA-Z][a-zA-Z0-9\-]*)\b[^>]*?\s([a-zA-Z\-]+)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
    re.I | re.S,
)

META_TAG_RE = re.compile(
    r"""<meta\s[^>]*?(?:content|url)\s*=\s*(?:"([^"]+)"|'([^']+)')[^>]*?>""",
    re.I | re.S,
)
OG_URL_RE = re.compile(
    r"""<meta[^>]*?property\s*=\s*["']og:(?:url|image)["'][^>]*?content\s*=\s*(?:"([^"]+)"|'([^']+)')""",
    re.I | re.S,
)

INLINE_JS_RE = re.compile(
    r"""<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>""",
    re.I | re.S,
)

URL_RE = re.compile(r"""https?://[^\s'"`<>)\]}]+""", re.I)

CSS_IMPORT_RE = re.compile(r"""@import\s+(?:url\()?["']?([^"')]+)["']?\)?\s*;?""", re.I)
CSS_URL_RE = re.compile(r"""url\(\s*["']?([^"')]+)["']?\s*\)""", re.I)

JS_IMPORT_RE = re.compile(r"""\bimport\s*\(?\s*['"]([^'"]+)['"]""")
JS_REQUIRE_RE = re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)""")
JS_FETCH_RE = re.compile(r"""\bfetch\s*\(\s*['"]([^'"]+)['"]""")
JS_AXIOS_RE = re.compile(r"""\baxios\.(?:get|post|put|delete|patch|head|request)\s*\(\s*['"]([^'"]+)['"]""")
JS_URL_CTOR_RE = re.compile(r"""\bnew\s+URL\s*\(\s*['"]([^'"]+)['"]""")
JS_LOCATION_RE = re.compile(r"""\b(?:\bwindow\.)?location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""")
JS_XHR_RE = re.compile(r"""\.(?:open|send)\s*\(\s*['"]([^'"]+)['"]""")

STATIC_EXTS = {
    ".js", ".mjs", ".css", ".json", ".xml", ".txt", ".map",
    ".svg", ".webp", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".pdf", ".zip", ".woff", ".woff2", ".ttf", ".eot",
    ".yml", ".yaml", ".md", ".csv",
}


def _is_same_domain(url: str, base_domain: str) -> bool:
    try:
        host = urlparse(url).netloc.split(":")[0]
        return host == base_domain or host.endswith("." + base_domain)
    except Exception:
        return False


def _clean_link(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return ""
    return raw


def _extract_html_links(html: str, base_url: str) -> list[str]:
    """从 HTML 中抽取所有 a/link/script/img/iframe 等标签的 URL."""
    links: set[str] = set()

    for tag, attr in HTML_TAGS:
        for m in HTML_TAG_RE.finditer(html):
            if m.group(1).lower() != tag.lower():
                continue
            for g in m.groups()[1:]:
                if g:
                    cleaned = _clean_link(g)
                    if cleaned:
                        abs_url = urljoin(base_url, cleaned)
                        if abs_url.startswith(("http://", "https://")):
                            links.add(abs_url)
                    break

    for m in META_TAG_RE.finditer(html):
        for g in m.groups():
            if g:
                cleaned = _clean_link(g)
                if cleaned:
                    abs_url = urljoin(base_url, cleaned)
                    if abs_url.startswith(("http://", "https://")):
                        links.add(abs_url)
                break

    for m in OG_URL_RE.finditer(html):
        for g in m.groups():
            if g:
                cleaned = _clean_link(g)
                if cleaned:
                    abs_url = urljoin(base_url, cleaned)
                    if abs_url.startswith(("http://", "https://")):
                        links.add(abs_url)
                break

    for m in INLINE_JS_RE.finditer(html):
        script_text = m.group(1)
        for u in _extract_js_urls(script_text, base_url):
            links.add(u)

    return sorted(links)


def _extract_css_urls(css_text: str, base_url: str) -> list[str]:
    """从 CSS 中抽取 @import / url() 等 URL."""
    out: set[str] = set()
    for pat in (CSS_IMPORT_RE, CSS_URL_RE):
        for m in pat.finditer(css_text):
            raw = (m.group(1) or "").strip()
            cleaned = _clean_link(raw)
            if not cleaned:
                continue
            abs_url = urljoin(base_url, cleaned)
            if abs_url.startswith(("http://", "https://")):
                out.add(abs_url)
    return sorted(out)


def _extract_js_urls(js_text: str, base_url: str) -> list[str]:
    """从 JS 文本里抽所有可能 URL."""
    out: set[str] = set()

    for pat in (
        JS_IMPORT_RE, JS_REQUIRE_RE, JS_FETCH_RE, JS_AXIOS_RE,
        JS_URL_CTOR_RE, JS_LOCATION_RE, JS_XHR_RE,
    ):
        for m in pat.finditer(js_text):
            raw = (m.group(1) or "").strip()
            cleaned = _clean_link(raw)
            if not cleaned:
                continue
            abs_url = urljoin(base_url, cleaned)
            if abs_url.startswith(("http://", "https://")):
                out.add(abs_url)
                continue
            if cleaned.startswith("/"):
                out.add(urljoin(base_url, cleaned))

    for m in URL_RE.finditer(js_text):
        u = m.group(0).rstrip(".,;)]}\"'")
        if u.startswith(("http://", "https://")):
            out.add(u)

    return sorted(out)


def _extract_json_urls(json_text: str, base_url: str) -> list[str]:
    out: set[str] = set()
    for m in URL_RE.finditer(json_text):
        u = m.group(0).rstrip(".,;)]}\"'")
        if u.startswith(("http://", "https://")):
            out.add(u)
    return sorted(out)


def _looks_like_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTS)


def _extract_static_urls(url: str, body: bytes, content_type: str) -> list[str]:
    """根据 content-type 和后缀, 调用合适的解析器."""
    ct = (content_type or "").lower()
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return []

    if "javascript" in ct or url.lower().split("?")[0].endswith((".js", ".mjs")):
        return _extract_js_urls(text, url)
    if "css" in ct or url.lower().endswith(".css"):
        return _extract_css_urls(text, url)
    if "json" in ct or url.lower().endswith(".json"):
        return _extract_json_urls(text, url)
    if "xml" in ct or url.lower().endswith(".xml"):
        return _extract_html_links(text, url)
    if "html" in ct or url.lower().endswith((".html", ".htm")):
        return _extract_html_links(text, url)
    return _extract_js_urls(text, url)


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


def _otx_domains(domain: str) -> set[str]:
    urls = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = http_get(url, timeout=12)
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


def _crawl(url: str, domain: str, depth: int, visited: set[str],
           results: list[dict], static_extracted: dict[str, int]) -> None:
    if depth > CRAWL_DEPTH or len(visited) > MAX_PAGES:
        return
    if url in visited:
        return
    visited.add(url)

    r = http_get(url, timeout=10)
    if not r:
        results.append({"url": url, "status": 0, "depth": depth, "size": 0,
                        "content_type": "", "links": 0, "extracted_static": 0})
        return

    body = r.content[:MAX_STATIC_BYTES]
    content_type = r.headers.get("content-type", "")
    status = r.status_code

    extracted_links: list[str] = []
    extracted_static_count = 0

    if "text/html" in content_type or url.lower().endswith((".html", ".htm")):
        html = body.decode("utf-8", errors="replace")
        extracted_links = _extract_html_links(html, url)
    elif _looks_like_static(url):
        try:
            extracted_links = _extract_static_urls(url, body, content_type)
            extracted_static_count = len(extracted_links)
            static_extracted[url] = extracted_static_count
        except Exception:
            extracted_links = []

    results.append({
        "url": url,
        "status": status,
        "size": len(body),
        "content_type": content_type,
        "depth": depth,
        "links": len(extracted_links),
        "extracted_static": extracted_static_count,
    })

    if depth + 1 > CRAWL_DEPTH:
        return

    for link in extracted_links:
        if _is_same_domain(link, domain) and link not in visited:
            _crawl(link, domain, depth + 1, visited, results, static_extracted)


def main() -> int:
    target = get_target()
    t0 = time.time()
    print(f"[urls] 目标: {target}", file=sys.stderr)

    all_urls: dict[str, list[str]] = {"wayback": [], "otx": [], "crawl": []}

    print("[urls] Wayback Machine 查询...", file=sys.stderr)
    wb = _wayback_urls(target)
    all_urls["wayback"] = sorted(wb)
    print(f"  {len(wb)} URLs", file=sys.stderr)

    print("[urls] OTX 查询...", file=sys.stderr)
    otx = _otx_domains(target)
    all_urls["otx"] = sorted(otx)
    print(f"  {len(otx)} 域名", file=sys.stderr)

    print("[urls] 深度爬取 (HTML + JS/CSS/JSON/XML 内嵌URL)...", file=sys.stderr)
    visited: set[str] = set()
    crawl_results: list[dict] = []
    static_extracted: dict[str, int] = {}

    _crawl(f"https://{target}", target, 0, visited, crawl_results, static_extracted)
    _crawl(f"http://{target}", target, 0, visited, crawl_results, static_extracted)

    crawl_urls: set[str] = set()
    for cr in crawl_results:
        crawl_urls.add(cr["url"])
    all_urls["crawl"] = sorted(crawl_urls)
    print(f"  {len(crawl_urls)} URLs (visited {len(visited)})", file=sys.stderr)
    print(f"  静态文件解析 {len(static_extracted)} 个, 抽到 URL 数: {sum(static_extracted.values())}", file=sys.stderr)

    all_combined = sorted(set(wb) | set(otx) | crawl_urls)

    paths: list[str] = []
    params: dict[str, int] = {}
    extensions: dict[str, int] = {}
    subdomains: set[str] = set()
    by_type: dict[str, int] = {"html": 0, "js": 0, "css": 0, "json": 0,
                                "xml": 0, "image": 0, "other": 0}

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
            if ext in (".html", ".htm"):
                by_type["html"] += 1
            elif ext in (".js", ".mjs"):
                by_type["js"] += 1
            elif ext == ".css":
                by_type["css"] += 1
            elif ext == ".json":
                by_type["json"] += 1
            elif ext == ".xml":
                by_type["xml"] += 1
            elif ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico"):
                by_type["image"] += 1
            else:
                by_type["other"] += 1

        host = parsed.netloc.split(":")[0]
        if host.endswith(target) and host != target:
            subdomains.add(host)

    unique_paths = sorted(set(paths))
    sorted_params = sorted(params.items(), key=lambda x: -x[1])
    sorted_exts = sorted(extensions.items(), key=lambda x: -x[1])

    elapsed = time.time() - t0
    print(f"\n[urls] 完成, 总 {len(all_combined)} URLs, {elapsed:.1f}s", file=sys.stderr)
    print(f"  路径: {len(unique_paths)}, 参数: {len(params)}, 子域名: {len(subdomains)}", file=sys.stderr)
    print(f"  按类型: {by_type}", file=sys.stderr)

    write_encrypted("urls", {
        "target": target,
        "total_urls": len(all_combined),
        "sources": {k: len(v) for k, v in all_urls.items()},
        "by_type": by_type,
        "urls": all_combined,
        "unique_paths": unique_paths,
        "unique_subdomains": sorted(subdomains),
        "top_params": dict(sorted_params[:50]),
        "file_extensions": dict(sorted_exts[:30]),
        "crawl_detail": crawl_results,
        "static_extracted_files": static_extracted,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
