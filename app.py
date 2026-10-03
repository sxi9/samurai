import gradio as gr
import json
import time
import httpx
from urllib.parse import urlparse, parse_qs
from tools.recon import analyze_headers, detect_tech, crawl_endpoints, dns_enum, check_common_paths
from tools.vuln_scanner import scan_url
from agents.pentest_ai import analyze_with_ai, generate_bug_bounty_report, generate_exploit_suggestions, chat
from config import SECURITY_MODEL, REPORT_MODEL

scan_results_store = {}


def run_scan(target_url, scan_depth, progress=gr.Progress()):
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    parsed = urlparse(target_url)
    domain = parsed.netloc
    results = {"target_info": {"url": target_url, "domain": domain}}
    logs = []

    progress(0.05, desc="Scanning security headers...")
    logs.append(f"[*] Scanning headers: {target_url}")
    yield "\n".join(logs), "", ""
    header_data = analyze_headers(target_url)
    results["headers"] = header_data
    logs.append(f"    Found {len(header_data.get('findings', []))} header issues")

    progress(0.15, desc="Detecting technology stack...")
    logs.append(f"[*] Detecting technology stack...")
    yield "\n".join(logs), "", ""
    tech = detect_tech(target_url)
    results["tech_stack"] = tech
    tech_list = [tech.get("server", ""), tech.get("cms", "")] + tech.get("frameworks", [])
    logs.append(f"    Detected: {', '.join(t for t in tech_list if t)}")

    progress(0.25, desc="Enumerating DNS...")
    logs.append(f"[*] DNS enumeration: {domain}")
    yield "\n".join(logs), "", ""
    dns_data = dns_enum(domain)
    results["dns"] = dns_data
    logs.append(f"    Subdomains found: {len(dns_data.get('subdomains', []))}")
    if dns_data.get("subdomains"):
        logs.append(f"    -> {', '.join(dns_data['subdomains'][:5])}")

    progress(0.35, desc="Checking common paths...")
    logs.append(f"[*] Checking exposed paths and files...")
    yield "\n".join(logs), "", ""
    paths = check_common_paths(target_url)
    results["exposed_paths"] = paths
    logs.append(f"    Found {len(paths)} accessible paths")
    for p in paths[:5]:
        logs.append(f"    -> [{p['status']}] {p['path']} ({p['severity']})")

    max_pages = {"Quick": 10, "Normal": 30, "Deep": 60}.get(scan_depth, 30)
    progress(0.45, desc=f"Crawling endpoints (max {max_pages} pages)...")
    logs.append(f"[*] Crawling endpoints (depth: {scan_depth})...")
    yield "\n".join(logs), "", ""
    crawl = crawl_endpoints(target_url, max_pages=max_pages)
    results["crawl"] = crawl
    logs.append(f"    Pages crawled: {crawl['pages_crawled']}")
    logs.append(f"    URLs: {len(crawl['urls'])} | Forms: {len(crawl['forms'])} | Params: {len(crawl['params'])}")
    logs.append(f"    API endpoints: {len(crawl['api_endpoints'])} | JS files: {len(crawl['js_files'])}")

    progress(0.60, desc="Testing for vulnerabilities...")
    logs.append(f"[*] Running vulnerability tests...")
    yield "\n".join(logs), "", ""
    all_vulns = []

    for form in crawl.get("forms", [])[:10]:
        params = {inp["name"]: inp.get("value", "test") for inp in form["inputs"] if inp.get("name")}
        if params:
            vulns = scan_url(form["action"], params)
            all_vulns.extend(vulns)

    for param_url in crawl.get("params", [])[:10]:
        p = urlparse(param_url)
        params = {k: v[0] for k, v in parse_qs(p.query).items()}
        if params:
            base = f"{p.scheme}://{p.netloc}{p.path}"
            vulns = scan_url(base, params)
            all_vulns.extend(vulns)

    results["vulnerabilities"] = all_vulns
    logs.append(f"    Vulnerabilities found: {len(all_vulns)}")
    for v in all_vulns:
        logs.append(f"    -> [{v['severity']}] {v['type']} in {v.get('param', 'N/A')}")

    progress(0.75, desc="AI analyzing results (WhiteRabbitNeo)...")
    logs.append(f"\n[*] AI analysis in progress (model: {SECURITY_MODEL})...")
    logs.append(f"    This may take 1-2 minutes...")
    yield "\n".join(logs), "", ""

    ai_report = analyze_with_ai(results)
    logs.append(f"[+] AI analysis complete!")

    scan_results_store["latest"] = results
    scan_results_store["vulns"] = all_vulns

    progress(1.0, desc="Scan complete!")
    logs.append(f"\n{'='*50}")
    logs.append(f"[+] SCAN COMPLETE")
    logs.append(f"    Total findings: {len(all_vulns) + len(header_data.get('findings', []))}")
    logs.append(f"    Critical: {sum(1 for v in all_vulns if v.get('severity') == 'CRITICAL')}")
    logs.append(f"    High: {sum(1 for v in all_vulns if v.get('severity') == 'HIGH')}")
    logs.append(f"    Medium: {sum(1 for v in all_vulns if v.get('severity') == 'MEDIUM')}")

    findings_summary = format_findings(all_vulns, header_data.get("findings", []))
    yield "\n".join(logs), ai_report, findings_summary


def format_findings(vulns, header_findings):
    lines = ["# Findings Summary\n"]
    if vulns:
        lines.append("## Vulnerability Findings\n")
        for i, v in enumerate(vulns, 1):
            lines.append(f"### {i}. [{v['severity']}] {v['type']}")
            lines.append(f"- **URL:** {v.get('url', 'N/A')}")
            lines.append(f"- **Parameter:** {v.get('param', 'N/A')}")
            lines.append(f"- **Payload:** `{v.get('payload', 'N/A')}`")
            lines.append(f"- **Evidence:** {v.get('evidence', 'N/A')}")
            lines.append("")
    if header_findings:
        lines.append("## Header Issues\n")
        for f in header_findings:
            lines.append(f"- **[{f['severity']}]** {f['issue']}")
    if not vulns and not header_findings:
        lines.append("*No vulnerabilities found by automated scanning.*")
        lines.append("*This does not mean the target is secure — manual testing is recommended.*")
    return "\n".join(lines)


def generate_report_for_finding(finding_index):
    vulns = scan_results_store.get("vulns", [])
    if not vulns:
        return "No scan results available. Run a scan first."
    idx = min(int(finding_index) - 1, len(vulns) - 1)
    if idx < 0:
        return "Invalid finding index."
    return generate_bug_bounty_report(vulns[idx])


def generate_exploit_for_finding(finding_index):
    vulns = scan_results_store.get("vulns", [])
    if not vulns:
        return "No scan results available. Run a scan first."
    idx = min(int(finding_index) - 1, len(vulns) - 1)
    if idx < 0:
        return "Invalid finding index."
    return generate_exploit_suggestions(vulns[idx])


def chat_fn(message, history):
    tuples_history = []
    for msg in history:
        if isinstance(msg, dict):
            if msg["role"] == "user":
                tuples_history.append((msg["content"], ""))
            elif msg["role"] == "assistant" and tuples_history:
                tuples_history[-1] = (tuples_history[-1][0], msg["content"])
        elif isinstance(msg, (list, tuple)):
            tuples_history.append(tuple(msg))
    response = chat(message, tuples_history)
    return response


CUSTOM_CSS = """
.main-title { text-align: center; margin-bottom: 0; }
.subtitle { text-align: center; opacity: 0.7; font-size: 14px; margin-top: 4px; }
.severity-critical { color: #ff1744; font-weight: bold; }
.severity-high { color: #ff6d00; font-weight: bold; }
.severity-medium { color: #ffc400; font-weight: bold; }
.severity-low { color: #00e676; font-weight: bold; }
footer { display: none !important; }
"""

with gr.Blocks(
    title="SamurAI — AI Pentest Tool",
) as app:
    gr.Markdown("# SamurAI", elem_classes="main-title")
    gr.Markdown(
        "AI-Powered Web Penetration Testing Tool — "
        f"Security: **{SECURITY_MODEL}** | Reports: **{REPORT_MODEL}**",
        elem_classes="subtitle",
    )

    with gr.Tabs():
        with gr.TabItem("Scanner", id="scanner"):
            with gr.Row():
                with gr.Column(scale=2):
                    target_input = gr.Textbox(
                        label="Target URL",
                        placeholder="https://example.com",
                        info="Enter the target URL to scan (authorized targets only)",
                    )
                with gr.Column(scale=1):
                    depth_input = gr.Radio(
                        ["Quick", "Normal", "Deep"],
                        value="Normal",
                        label="Scan Depth",
                    )
            scan_btn = gr.Button("Launch Scan", variant="primary", size="lg")

            with gr.Row():
                scan_log = gr.Textbox(
                    label="Scan Log",
                    lines=15,
                    interactive=False,
                )
            with gr.Row():
                with gr.Column():
                    ai_report = gr.Markdown(label="AI Pentest Report")
                with gr.Column():
                    findings_md = gr.Markdown(label="Findings")

            scan_btn.click(
                fn=run_scan,
                inputs=[target_input, depth_input],
                outputs=[scan_log, ai_report, findings_md],
            )

        with gr.TabItem("Bug Bounty Reporter", id="reporter"):
            gr.Markdown("### Generate Submission-Ready Reports")
            gr.Markdown("Run a scan first, then select a finding number to generate a detailed report.")
            with gr.Row():
                finding_idx = gr.Number(
                    label="Finding # (from scan results)",
                    value=1,
                    minimum=1,
                    precision=0,
                )
            with gr.Row():
                report_btn = gr.Button("Generate Bug Bounty Report", variant="primary")
                exploit_btn = gr.Button("Generate Exploit Guide", variant="secondary")
            report_output = gr.Markdown(label="Generated Report")

            report_btn.click(
                fn=generate_report_for_finding,
                inputs=[finding_idx],
                outputs=[report_output],
            )
            exploit_btn.click(
                fn=generate_exploit_for_finding,
                inputs=[finding_idx],
                outputs=[report_output],
            )

        with gr.TabItem("AI Chat", id="chat"):
            gr.Markdown("### Security Expert Chat")
            gr.Markdown(
                "Ask anything — payloads, exploitation techniques, "
                "WAF bypasses, reverse shells, privilege escalation. No restrictions."
            )
            chatbot = gr.ChatInterface(
                fn=chat_fn,
                examples=[
                    "Generate XSS payloads that bypass common WAFs",
                    "How to escalate from SSRF to RCE?",
                    "Write a reverse shell payload in Python",
                    "Explain blind SQL injection techniques with examples",
                    "How to find and exploit IDOR vulnerabilities?",
                    "Create a wordlist for subdomain brute-forcing",
                ],
            )

        with gr.TabItem("Payload Generator", id="payloads"):
            gr.Markdown("### Quick Payload Generator")
            with gr.Row():
                vuln_type = gr.Dropdown(
                    [
                        "XSS (Reflected)",
                        "XSS (Stored)",
                        "XSS (DOM-based)",
                        "SQL Injection",
                        "SQL Injection (Blind)",
                        "SSTI",
                        "SSRF",
                        "LFI / Path Traversal",
                        "Command Injection",
                        "XXE",
                        "Open Redirect",
                        "CSRF",
                        "Reverse Shell",
                        "Web Shell",
                    ],
                    label="Vulnerability Type",
                    value="XSS (Reflected)",
                )
                context_input = gr.Textbox(
                    label="Context (optional)",
                    placeholder="e.g., PHP backend, behind Cloudflare WAF, input in href attribute...",
                )
            gen_payload_btn = gr.Button("Generate Payloads", variant="primary")
            payload_output = gr.Markdown(label="Payloads")

            def gen_payloads(vuln, context):
                extra = f"\nAdditional context: {context}" if context else ""
                msg = f"Generate 10 working payloads for {vuln} attacks.{extra}\n\nFor each payload:\n1. The raw payload\n2. URL-encoded version\n3. What it does\n4. WAF bypass variant\n\nAlso include any relevant tips for this specific attack type."
                return chat(msg, [])

            gen_payload_btn.click(
                fn=gen_payloads,
                inputs=[vuln_type, context_input],
                outputs=[payload_output],
            )

    gr.Markdown(
        "---\n*SamurAI — Self-hosted AI pentest tool. "
        "For authorized security testing only. "
        "Powered by WhiteRabbitNeo + Qwen 72B on NVIDIA H200.*"
    )


if __name__ == "__main__":
    app.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        theme=gr.themes.Base(
            primary_hue="red",
            secondary_hue="orange",
            neutral_hue="slate",
            font=gr.themes.GoogleFont("Inter"),
        ),
        css=CUSTOM_CSS,
    )
