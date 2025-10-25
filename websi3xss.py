#!/usr/bin/env python3
"""
websi3xss.py (patched)
Writes HTML report even when no vulnerable URLs are found if --always-report is used,
or always writes when --report is provided and --always-report is set.
"""

import os
import sys
import time
import argparse
import urllib.parse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Tuple

# Color for banner and output
from colorama import Fore, Style, init
import sys
# detect if stdout is a TTY; if not, strip ANSI when printing (safe for redirects)
_is_tty = sys.stdout.isatty()
init(autoreset=True, strip=not _is_tty)

# --- Banner ---
print(f"""{Fore.CYAN}
██╗    ██╗███████╗██████╗ ███████╗██╗██╗██████╗ 
██║    ██║██╔════╝██╔══██╗██╔════╝██║██║██╔══██╗
██║ █╗ ██║███████╗██████╔╝███████╗██║██║██║  ██║
██║███╗██║╚════██║██╔═══╝ ╚════██║██║██║██║  ██║
╚███╔███╔╝███████║██║     ███████║██║██║██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═╝     ╚══════╝╚═╝╚═╝╚═════╝ 
{Fore.YELLOW}       Websi3 Scanner v1.0 — XSS Detection
{Style.RESET_ALL}
""")

# --- Configuration defaults ---
DEFAULT_TIMEOUT = 15.0
DEFAULT_THREADS = 4
DETECT_HOSTS = ["google.com"]  # you can add more hosts/patterns to treat as "redirect destination"

# --- Utilities ---
def load_lines_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def ensure_url_has_scheme(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

# --- Selenium driver factory ---
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

def make_driver(headless: bool = True, timeout: float = DEFAULT_TIMEOUT):
    chrome_options = Options()
    if headless:
        chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-infobars")
    chrome_options.add_argument("--disable-notifications")
    chrome_options.page_load_strategy = "eager"
    logging.getLogger("WDM").setLevel(logging.ERROR)
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(timeout)
    return driver

# --- Core checking function ---
def check_payload_with_selenium(test_url: str, payload: str, param_name: str,
                                timeout: float, headless: bool) -> Tuple[bool, str, str]:
    try:
        driver = make_driver(headless=headless, timeout=timeout)
    except Exception as e:
        return False, "", f"driver_error: {e}"

    try:
        driver.get(test_url)
        WebDriverWait(driver, min(10, int(timeout))).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        final_url = driver.current_url.lower()
        for host in DETECT_HOSTS:
            if host in final_url:
                return True, final_url, f"{Fore.RED}redirected_to_{host}{Style.RESET_ALL}"
        return False, final_url, f"{Fore.GREEN}no_redirect_detected{Style.RESET_ALL}"
    except Exception as e:
        return False, "", f"{Fore.YELLOW}error: {str(e)}{Style.RESET_ALL}"
    finally:
        try:
            driver.quit()
        except:
            pass

# --- Build test URLs ---
def build_test_urls_for_payloads(base_url: str, payloads: List[str]) -> List[Tuple[str, str, str]]:
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.scheme:
        parsed = urllib.parse.urlparse("http://" + base_url)
    test_list = []
    if parsed.query:
        pairs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for payload in payloads:
            for param in pairs.keys():
                copy_pairs = {k: list(v) for k, v in pairs.items()}
                copy_pairs[param] = [payload]
                new_query = urllib.parse.urlencode(copy_pairs, doseq=True)
                new_parsed = parsed._replace(query=new_query)
                test_list.append((urllib.parse.urlunparse(new_parsed), payload, param))
    else:
        path = parsed.path if parsed.path else ""
        for payload in payloads:
            new_path = path + payload
            new_parsed = parsed._replace(path=new_path)
            test_list.append((urllib.parse.urlunparse(new_parsed), payload, "path"))
    return test_list

# --- HTML report ---
def generate_html_report(title: str, found: int, scanned: int, duration_s: int, vulnerable_urls: List[str]) -> str:
    timestamp = datetime.utcnow().isoformat() + "Z"
    if vulnerable_urls:
        items = "\n".join(f"<li class=\"vuln-item\"><a href=\"{u}\" rel=\"noreferrer\">{u}</a></li>" for u in vulnerable_urls)
    else:
        items = "<li class=\"muted\">None</li>"

    css = (
        "<style>"
        " :root{--bg:#0f1724;--card:#0b1220;--muted:#94a3b8;--accent:#60a5fa;--good:#10b981;--bad:#ef4444;--glass:rgba(255,255,255,0.04)}"
        " body{background:linear-gradient(180deg,#071027 0%, #04111b 100%);color:#e6eef8;font-family:Inter,Segoe UI,Helvetica,Arial,sans-serif;padding:24px}" 
        " .container{max-width:900px;margin:24px auto;padding:18px;background:var(--card);border-radius:12px;box-shadow:0 6px 24px rgba(2,6,23,0.6);}" 
        " h1{font-size:20px;margin:0 0 8px 0;color:var(--accent)}"
        " .meta{color:var(--muted);margin-bottom:12px}"
        " .stats{display:flex;gap:12px;margin:12px 0}"
        " .stat{background:var(--glass);padding:10px 14px;border-radius:8px}"
        " .stat b{display:block;font-size:18px}"
        " ol{margin:8px 0 0 18px}"
        " a{color:var(--accent);text-decoration:none}"
        " a:hover{text-decoration:underline}"
        " .muted{color:var(--muted);font-style:italic}"
        " .vuln-item a{color:var(--bad)}"
        " .footer{margin-top:18px;color:var(--muted);font-size:13px}"
        " .legend{display:flex;gap:8px;align-items:center;margin-top:6px}"
        " .dot{width:10px;height:10px;border-radius:50%;display:inline-block}"
        " .dot.good{background:var(--good)}.dot.bad{background:var(--bad)}.dot.muted{background:var(--muted)}"
        " @media (max-width:600px){.stats{flex-direction:column}}"
        "</style>"
    )

    header_html = (
        "<header style=\"display:flex;align-items:center;gap:12px;margin-bottom:8px\">"
        "<div style=\"font-family:monospace;font-weight:700;color:#60a5fa;font-size:26px\">WEBSI3</div>"
        "<div style=\"color:#94a3b8;margin-left:8px;font-size:14px\">Scanner v1.0 — XSS  Detection</div>"
        "</header>"
    )

    html = (
        "<!doctype html>"
        "<html>"
        "<head>"
        "  <meta charset=\"utf-8\">"
        "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"  <title>{title} - Report</title>"
        f"  {css}"
        "</head>"
        "<body>"
        "  <div class=\"container\">"
        f"    {header_html}"
        "    <div class=\"meta\">Timestamp (UTC): " + timestamp + "</div>"

        "    <div class=\"stats\">"
        f"      <div class=\"stat\"><span class=\"dot bad\"></span> <small>Total vulnerable</small><b>{found}</b></div>"
        f"      <div class=\"stat\"><span class=\"dot muted\"></span> <small>Total scanned</small><b>{scanned}</b></div>"
        f"      <div class=\"stat\"><span class=\"dot muted\"></span> <small>Time taken (s)</small><b>{duration_s}</b></div>"
        "    </div>"

        "    <h2>Vulnerable URLs</h2>"
        "    <ol>"
        f"      {items}"
        "    </ol>"

        "    <div class=\"legend\">"
        "      <div class=\"dot bad\"></div><small> vulnerable</small>"
        "      <div style=\"width:8px\"></div>"
        "      <div class=\"dot muted\"></div><small>no findings / scanned</small>"
        "    </div>"

        "    <div class=\"footer\">Generated by Websi3 Scanner</div>"
        "  </div>"
        "</body>"
        "</html>"
    )
    return html

# --- Main runner ---
def run_scan_on_url(url: str, payloads: List[str], threads: int, timeout: float, headless: bool):
    test_entries = build_test_urls_for_payloads(url, payloads)
    total_scanned = 0
    found = 0
    vulnerable_urls = []
    start = time.time()

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = []
        for test_url, payload, param in test_entries:
            futures.append(exe.submit(check_payload_with_selenium, test_url, payload, param, timeout, headless))

        for (test_url, payload, param), fut in zip(test_entries, futures):
            total_scanned += 1
            try:
                vulnerable, final_url, message = fut.result(timeout=timeout + 5)
            except Exception as e:
                vulnerable, final_url, message = False, "", f"future_error:{e}"
            if vulnerable:
                found += 1
                vulnerable_urls.append(test_url)
                print(f"{Fore.RED}[✓] Vulnerable:{Style.RESET_ALL} {test_url} → {final_url} ({message})")
            else:
                print(f"{Fore.GREEN}[✗] Not vulnerable:{Style.RESET_ALL} {test_url} ({message})")

    duration = int(time.time() - start)
    return found, total_scanned, vulnerable_urls, duration

# --- CLI / entrypoint ---
def main():
    parser = argparse.ArgumentParser(description="Websi3 Selenium-based XSS  tester")
    parser.add_argument("--url", help="Single URL to scan")
    parser.add_argument("--urls", help="File with newline-separated URLs")
    parser.add_argument("--payloads", help="File with payloads")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--no-headless", action="store_false", dest="headless")
    parser.add_argument("--report", help="Save HTML report to this path")
    parser.add_argument("--always-report", action="store_true", help="Write report even when no findings")
    args = parser.parse_args()

    if not args.url and not args.urls:
        parser.print_help()
        sys.exit(1)

    if args.payloads:
        if not os.path.isfile(args.payloads):
            print(f"[!] Payload file not found: {args.payloads}")
            sys.exit(1)
        payloads = load_lines_from_file(args.payloads)
    else:
        payloads = [
            "https://google.com",
            "//google.com",
            "/%2F%2Fgoogle.com",
            "?redirect=https://google.com",
            "javascript:alert(1)"
        ]

    targets = []
    if args.urls:
        if not os.path.isfile(args.urls):
            print(f"[!] URLs file not found: {args.urls}")
            sys.exit(1)
        targets = load_lines_from_file(args.urls)
    if args.url:
        targets.append(args.url)

    global_start = time.time()
    total_found_all = 0
    total_scanned_all = 0
    all_vulnerable_urls = []

    for target in targets:
        print(f"\n{Fore.YELLOW}=== Scanning target:{Style.RESET_ALL} {target}")
        found, scanned, vulnerable_urls, duration = run_scan_on_url(target, payloads, args.threads, args.timeout, args.headless)
        total_found_all += found
        total_scanned_all += scanned
        all_vulnerable_urls.extend(vulnerable_urls)
        print(f"{Fore.CYAN}[i] Completed target:{Style.RESET_ALL} found={found}, scanned={scanned}, time={duration}s")

    global_duration = int(time.time() - global_start)
    print(f"\n{Fore.MAGENTA}=== Summary ==={Style.RESET_ALL}")
    print(f"{Fore.RED}Total found:{Style.RESET_ALL} {total_found_all}")
    print(f"{Fore.GREEN}Total scanned:{Style.RESET_ALL} {total_scanned_all}")
    print(f"{Fore.YELLOW}Time taken:{Style.RESET_ALL} {global_duration}s")

    # Write report if --report provided and either vulnerabilities exist OR --always-report is set
    if args.report and (all_vulnerable_urls or args.always_report):
        # ensure directory exists
        report_dir = os.path.dirname(os.path.abspath(args.report))
        if report_dir and not os.path.isdir(report_dir):
            try:
                os.makedirs(report_dir, exist_ok=True)
            except Exception as e:
                print(f"[!] Could not create report directory {report_dir}: {e}")
                sys.exit(1)

        html = generate_html_report("Websi3 Scan", total_found_all, total_scanned_all, global_duration, all_vulnerable_urls)
        try:
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"{Fore.CYAN}[✓] Report saved to {args.report}{Style.RESET_ALL}")
        except Exception as e:
            print(f"[!] Failed to write report: {e}")
    elif args.report:
        print(f"[i] No vulnerabilities found and --always-report not set; report not written to {args.report}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
