import httpx
import dns.resolver
import socket
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


def analyze_headers(url: str) -> dict:
    findings = []
    try:
        r = httpx.get(url, follow_redirects=True, timeout=15, verify=False)
        headers = dict(r.headers)

        security_headers = {
            "strict-transport-security": "HSTS not set — vulnerable to SSL stripping",
            "x-content-type-options": "X-Content-Type-Options missing — MIME sniffing possible",
            "x-frame-options": "X-Frame-Options missing — clickjacking possible",
            "content-security-policy": "CSP missing — XSS risk increased",
            "x-xss-protection": "X-XSS-Protection missing",
            "referrer-policy": "Referrer-Policy missing — information leakage possible",
            "permissions-policy": "Permissions-Policy missing",
        }

        for header, issue in security_headers.items():
            if header not in {k.lower() for k in headers}:
                findings.append({"severity": "MEDIUM", "issue": issue})

        if "server" in {k.lower() for k in headers}:
            server = headers.get("Server", headers.get("server", ""))
            findings.append({"severity": "LOW", "issue": f"Server header exposes: {server}"})

        if "x-powered-by" in {k.lower() for k in headers}:
            powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
            findings.append({"severity": "LOW", "issue": f"X-Powered-By exposes: {powered}"})

        cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
        for cookie in cookies:
            if "secure" not in cookie.lower():
                findings.append({"severity": "MEDIUM", "issue": f"Cookie without Secure flag: {cookie[:60]}"})
            if "httponly" not in cookie.lower():
                findings.append({"severity": "MEDIUM", "issue": f"Cookie without HttpOnly flag: {cookie[:60]}"})

        return {"headers": headers, "findings": findings, "status_code": r.status_code}
    except Exception as e:
        return {"error": str(e), "findings": findings}


def detect_tech(url: str) -> dict:
    tech = {"server": None, "frameworks": [], "javascript": [], "cms": None, "cdn": None}
    try:
        r = httpx.get(url, follow_redirects=True, timeout=15, verify=False)
        html = r.text
        headers = {k.lower(): v for k, v in r.headers.items()}

        tech["server"] = headers.get("server", "Unknown")

        if headers.get("x-powered-by"):
            tech["frameworks"].append(headers["x-powered-by"])

        patterns = {
            "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
            "Drupal": [r"drupal", r"sites/default/files"],
            "Joomla": [r"joomla", r"/components/com_"],
            "React": [r"react", r"_react", r"__NEXT_DATA__"],
            "Angular": [r"ng-version", r"angular"],
            "Vue.js": [r"vue\.js", r"__vue__"],
            "jQuery": [r"jquery"],
            "Bootstrap": [r"bootstrap"],
            "Laravel": [r"laravel", r"csrf-token"],
            "Django": [r"csrfmiddlewaretoken", r"django"],
            "Express": [r"express"],
            "Flask": [r"flask"],
            "Spring": [r"spring", r"jsessionid"],
            "ASP.NET": [r"__viewstate", r"asp\.net"],
            "PHP": [r"\.php", r"PHPSESSID"],
            "Nginx": [r"nginx"],
            "Apache": [r"apache"],
            "Cloudflare": [r"cloudflare", r"cf-ray"],
        }

        html_lower = html.lower()
        headers_str = str(headers).lower()
        combined = html_lower + headers_str

        for name, pats in patterns.items():
            for pat in pats:
                if re.search(pat, combined, re.I):
                    if name in ["Cloudflare"]:
                        tech["cdn"] = name
                    elif name in ["WordPress", "Drupal", "Joomla"]:
                        tech["cms"] = name
                    else:
                        tech["frameworks"].append(name)
                    break

        tech["frameworks"] = list(set(tech["frameworks"]))
        return tech
    except Exception as e:
        return {"error": str(e), **tech}


def crawl_endpoints(url: str, max_pages: int = 30) -> dict:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    visited = set()
    found_urls = set()
    forms = []
    params = set()
    js_files = []
    api_endpoints = set()

    to_visit = [url]
    while to_visit and len(visited) < max_pages:
        current = to_visit.pop(0)
        if current in visited:
            continue
        visited.add(current)

        try:
            r = httpx.get(current, follow_redirects=True, timeout=10, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = urljoin(current, a["href"])
                if href.startswith(base) and href not in visited:
                    found_urls.add(href)
                    to_visit.append(href)
                if "?" in href:
                    params.add(href)

            for form in soup.find_all("form"):
                action = urljoin(current, form.get("action", ""))
                method = form.get("method", "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    inputs.append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                forms.append({"action": action, "method": method, "inputs": inputs, "page": current})

            for script in soup.find_all("script", src=True):
                src = urljoin(current, script["src"])
                if src.startswith(base):
                    js_files.append(src)

            api_patterns = re.findall(r'["\'](/api/[^"\']+)["\']', r.text)
            for ep in api_patterns:
                api_endpoints.add(urljoin(base, ep))

        except Exception:
            continue

    return {
        "urls": list(found_urls)[:50],
        "forms": forms,
        "params": list(params),
        "js_files": list(set(js_files)),
        "api_endpoints": list(api_endpoints),
        "pages_crawled": len(visited),
    }


def dns_enum(domain: str) -> dict:
    results = {"a": [], "aaaa": [], "mx": [], "ns": [], "txt": [], "cname": []}
    for rtype in results:
        try:
            answers = dns.resolver.resolve(domain, rtype.upper())
            results[rtype] = [str(r) for r in answers]
        except Exception:
            pass

    common_subs = ["www", "mail", "ftp", "admin", "dev", "staging", "api", "test",
                   "beta", "portal", "vpn", "remote", "cdn", "app", "shop", "blog",
                   "forum", "git", "jenkins", "ci", "docs", "status", "monitor"]
    subdomains = []
    for sub in common_subs:
        try:
            fqdn = f"{sub}.{domain}"
            socket.getaddrinfo(fqdn, None)
            subdomains.append(fqdn)
        except (socket.gaierror, OSError):
            pass

    results["subdomains"] = subdomains
    return results


def check_common_paths(url: str) -> list:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = [
        "/.env", "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
        "/.htaccess", "/wp-admin/", "/admin/", "/administrator/",
        "/phpmyadmin/", "/server-status", "/server-info",
        "/.well-known/security.txt", "/backup/", "/backup.zip", "/backup.sql",
        "/db.sql", "/dump.sql", "/config.php", "/config.yml", "/config.json",
        "/.DS_Store", "/web.config", "/crossdomain.xml", "/elmah.axd",
        "/trace.axd", "/debug/", "/.svn/entries", "/api/", "/api/v1/",
        "/graphql", "/swagger.json", "/api-docs", "/openapi.json",
        "/actuator", "/actuator/health", "/actuator/env",
        "/.aws/credentials", "/wp-config.php.bak", "/info.php", "/phpinfo.php",
    ]
    found = []
    for path in paths:
        try:
            r = httpx.get(f"{base}{path}", follow_redirects=False, timeout=5, verify=False)
            if r.status_code in [200, 301, 302, 403]:
                found.append({
                    "path": path,
                    "status": r.status_code,
                    "size": len(r.content),
                    "severity": "HIGH" if path in ["/.env", "/.git/config", "/.aws/credentials", "/backup.sql", "/db.sql"] else "MEDIUM"
                })
        except Exception:
            pass
    return found
