from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from _common import _read_encrypted, write_encrypted, http_get, load_wordlist

COMMON_PARAMS = [
    "id", "uid", "user_id", "page", "p", "limit", "size",
    "offset", "skip", "sort", "order",
    "filter", "q", "query", "search", "s",
    "lang", "debug", "test", "mode",
    "callback", "format", "fmt",
    "api_key", "key", "token", "secret",
    "redirect", "url", "next", "return",
    "file", "path", "dir", "folder",
    "action", "cmd", "exec", "run",
    "type", "cat", "tag", "category",
    "v", "version", "ver",
    "name", "title", "slug", "permalink",
    "email", "phone", "user", "username",
    "password", "pass", "pwd",
    "admin", "config", "setting", "option",
    "theme", "template", "layout",
    "view", "display", "show", "load",
    "method", "func", "function", "ajax",
    "data", "json", "xml", "raw",
    "sign", "hash", "hmac", "nonce",
    "ts", "time", "date", "expires",
    "locale", "region", "country",
    "provider", "source", "from",
    "target", "dest", "destination",
    "width", "height", "size",
    "color", "bg", "fg",
    "status", "state", "flag",
    "include", "require", "import",
    "class", "interface", "handler",
    "module", "component",
    "zone", "scope", "section",
    "ref", "referer", "origin",
    "signature", "sig",
    "continue", "retry",
    "verify", "validate", "confirm",
    "agree", "consent",
    "lang", "language",
    "tz", "timezone",
    "page", "per_page", "page_size",
    "since", "before", "after",
    "min", "max", "range",
    "lat", "lon", "long",
    "address", "location",
    "phone", "tel",
    "code", "pin", "otp",
    "session", "sid",
    "csrf", "token",
    "nonce", "state",
    "scope", "grant",
    "response_type", "client_id",
    "client_secret", "redirect_uri",
    "domain", "host", "port",
    "protocol", "scheme",
    "ip", "ip_address",
    "user_agent", "ua",
    "referer", "referrer",
    "origin", "sec_origin",
    "x_for", "x_real_ip",
    "cf_ray", "cf_ip",
    "amzn_trace_id",
    "cloudfront_viewer",
    "akamai_origin",
    "akamai_cache",
    "true_client_ip",
]


def check_param(url: str, param: str) -> dict | None:
    sep = "&" if "?" in url else "?"
    url_with = f"{url}{sep}{param}=test"
    url_without = url

    r1 = http_get(url_with, timeout=5)
    r2 = http_get(url_without, timeout=5)

    if not r1 or not r2:
        return None

    len1, len2 = len(r1.content), len(r2.content)
    if abs(len1 - len2) > max(len2 * 0.05, 50):
        return {
            "param": param,
            "url": url,
            "status_with": r1.status_code,
            "status_without": r2.status_code,
            "size_diff": len1 - len2,
        }
    return None


def main() -> int:
    print("[param] 读取 urls", file=sys.stderr)
    udata = _read_encrypted("urls")
    target = udata.get("target", "")
    print(f"[param] 目标: {target}", file=sys.stderr)

    all_urls = udata.get("urls", [])
    discovered_params = list(udata.get("top_params", {}).keys())

    wordlist_raw = load_wordlist("params")
    custom_params = list(dict.fromkeys(discovered_params + COMMON_PARAMS))
    if wordlist_raw:
        custom_params = list(dict.fromkeys(discovered_params + wordlist_raw))
    else:
        custom_params = list(dict.fromkeys(discovered_params + COMMON_PARAMS))

    test_urls = [u for u in all_urls if "?" not in urlparse(u).query]
    if not test_urls:
        test_urls = all_urls[:20]
    test_urls = test_urls[:50]

    print(f"[param] 参数: {len(custom_params)}, 目标 URL: {len(test_urls)}", file=sys.stderr)

    t0 = time.time()
    all_found: list[dict] = []

    for url in test_urls:
        with ThreadPoolExecutor(max_workers=30) as ex:
            futs = {ex.submit(check_param, url, p): p for p in custom_params}
            for fut in as_completed(futs):
                r = fut.result()
                if r:
                    all_found.append(r)
                    print(f"  [HIT] {r['param']} @ {url} diff={r['size_diff']}", file=sys.stderr)

    elapsed = time.time() - t0
    print(f"\n[param] {len(all_found)} 命中, {elapsed:.1f}s", file=sys.stderr)

    write_encrypted("params", {
        "target": target,
        "params_tested": len(custom_params),
        "urls_tested": len(test_urls),
        "found": all_found,
        "elapsed_s": round(elapsed, 1),
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
