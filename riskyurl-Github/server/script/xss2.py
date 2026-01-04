import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin
import re

# Payloads to test
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "\"><script>alert('xss')</script>",
    "'><img src=x onerror=alert('xss')>",
    "<svg/onload=alert('xss')>",
    "<body onload=alert('xss')>"
]

def print_progress(msg):
    print(f"[+] {msg}")
    time.sleep(0.5)

# Reflected XSS Testing
def test_reflected_xss(url):
    print_progress("Testing for Reflected XSS...")
    vulnerable_payloads = []

    base_url = url.split('?')[0]
    params = url.split('?')[1] if '?' in url else ''

    for payload in XSS_PAYLOADS:
        try:
            encoded_payload = requests.utils.quote(payload)
            test_url = f"{base_url}?{params}{encoded_payload}"

            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                print(f"[!!] Reflected XSS Detected with payload: {payload}")
                vulnerable_payloads.append(payload)
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {str(e)}")
            continue

    if not vulnerable_payloads:
        print("[-] No Reflected XSS found.")
    return vulnerable_payloads

# Stored XSS Testing
def test_stored_xss(url):
    print_progress("Testing for Stored XSS...")
    vulnerable_forms = []

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all("form", method=["post", "POST"])

        for form in forms:
            try:
                action = form.get("action")
                form_url = urljoin(url, action) if action else url
                inputs = form.find_all("input")

                data = {}
                for input_tag in inputs:
                    name = input_tag.get("name")
                    input_type = input_tag.get("type", "").lower()
                    if name and input_type not in ["submit", "button"]:
                        data[name] = XSS_PAYLOADS[0]

                if data:
                    post_response = requests.post(
                        form_url,
                        data=data,
                        timeout=5,
                        headers={'User-Agent': 'XSS-Scanner/1.0'}
                    )

                    # Check if payload is reflected back in response (basic heuristic)
                    if XSS_PAYLOADS[0] in post_response.text:
                        print("[!!] Potential Stored XSS Detected in form submission")
                        print(f"     Form action: {form_url}")
                        vulnerable_forms.append({
                            "form_action": form_url,
                            "payload": XSS_PAYLOADS[0]
                        })
            except Exception as e:
                print(f"[!] Error testing form: {str(e)}")
                continue

    except Exception as e:
        print(f"[ERROR] Failed Stored XSS test: {e}")

    if not vulnerable_forms:
        print("[-] No Stored XSS found (or no forms to test).")
    return vulnerable_forms

# DOM-Based XSS Testing
def test_dom_xss(url):
    print_progress("Testing for DOM-Based XSS...")
    detected_patterns = []

    try:
        response = requests.get(url, timeout=5)
        unsafe_patterns = [
            r"document\.write\(.*?\)",
            r"innerHTML\s*=",
            r"eval\(.*?\)",
            r"location\.hash",
            r"setTimeout\(.*?\)",
            r"setInterval\(.*?\)"
        ]

        for pattern in unsafe_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                detected_patterns.append(pattern)

        if detected_patterns:
            print("[!!] Potential DOM-Based XSS Detected. Unsafe JS patterns found:")
            for pattern in detected_patterns:
                print(f"     - {pattern}")
    except Exception as e:
        print(f"[ERROR] Failed DOM XSS check: {e}")

    if not detected_patterns:
        print("[-] No obvious DOM-Based XSS patterns detected.")
    return detected_patterns

def xss_checker(url: str):
    print("=== XSS Vulnerability Scanner ===")
    url = url.strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    print_progress(f"Starting XSS scan on {url}\n")

    results = {
        "reflected": [],
        "stored": [],
        "dom": [],
        "status": "success",
        "error": None
    }

    try:
        test_response = requests.get(url, timeout=5)
        if test_response.status_code != 200:
            error_msg = f"Error: Received HTTP {test_response.status_code} for URL"
            print(f"[X] {error_msg}")
            results["status"] = "error"
            results["error"] = error_msg
            return results

        reflected = test_reflected_xss(url)
        stored = test_stored_xss(url)
        dom = test_dom_xss(url)

        results["reflected"] = reflected
        results["stored"] = stored
        results["dom"] = dom

        print("\n=== Detailed Scan Results ===")
        if reflected:
            print("[🔴] Reflected XSS detected with these payloads:")
            for payload in reflected:
                print(f"     - {payload}")
        if stored:
            print("[🔴] Stored XSS detected in these forms:")
            for form in stored:
                print(f"     - Form: {form['form_action']} | Payload: {form['payload']}")
        if dom:
            print("[🔴] DOM-Based XSS indicators:")
            for pattern in dom:
                print(f"     - Pattern: {pattern}")

        if not any([reflected, stored, dom]):
            print("[🟢] No XSS vulnerabilities found with basic tests.")
            print("Note: Manual & browser-based testing is still recommended.")
        else:
            print("\n[⚠️] Recommendations:")
            print("- Sanitize and encode user input/output")
            print("- Implement CSP headers")
            print("- Avoid dangerous JavaScript functions (e.g., eval, innerHTML)")
            print("- Use security libraries like DOMPurify")

    except requests.RequestException as e:
        error_msg = f"Failed to access URL: {str(e)}"
        print(f"[X] {error_msg}")
        results["status"] = "error"
        results["error"] = error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"[X] {error_msg}")
        results["status"] = "error"
        results["error"] = error_msg

    return results
