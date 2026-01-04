import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time

def print_progress(message):
    print(f"[+] {message}")
    time.sleep(0.4)

# === GET-Based CSRF Check ===
def check_get_csrf(url):
    print_progress("Checking for GET-based CSRF...")
    try:
        if "?" in url:
            response = requests.get(url)
            if response.status_code in [200, 302] and "logout" in url.lower():
                print("[!!] GET-based CSRF detected (state-changing GET request found).")
                return True
        print("[-] No GET-based CSRF detected.")
    except Exception as e:
        print(f"[!] GET CSRF Check Error: {str(e)}")
    return False

# === POST-Based CSRF Check ===
def check_post_csrf(url):
    print_progress("Checking for POST-based CSRF...")
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")

        if not forms:
            print("[-] No POST forms found.")
            return False

        for form in forms:
            action = form.get("action")
            post_url = urljoin(url, action) if action else url
            inputs = form.find_all("input")
            data = {}
            for i in inputs:
                name = i.get("name")
                if name:
                    data[name] = "test"

            response = requests.post(post_url, data=data)
            if response.status_code in [200, 302]:
                print("[!!] POST-based CSRF potentially detected (no anti-CSRF token).")
                return True
        print("[-] No POST-based CSRF detected.")
    except Exception as e:
        print(f"[!] POST CSRF Check Error: {str(e)}")
    return False

# === JSON-Based CSRF Check ===
def check_json_csrf(url):
    print_progress("Checking for JSON-based CSRF...")
    try:
        headers = {
            "Content-Type": "application/json"
        }
        payload = '{"test":"csrf"}'
        response = requests.post(url, headers=headers, data=payload)
        if response.status_code in [200, 302]:
            print("[!!] JSON-based CSRF possible (server accepts unauthenticated JSON).")
            return True
        print("[-] No JSON-based CSRF detected.")
    except Exception as e:
        print(f"[!] JSON CSRF Check Error: {str(e)}")
    return False

# === Missing Anti-CSRF Token Check ===
def check_csrf_token(url):
    print_progress("Checking for missing anti-CSRF tokens...")
    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form", method=lambda m: m and m.lower() == "post")

        for form in forms:
            token_found = False
            for i in form.find_all("input"):
                if "csrf" in (i.get("name") or "").lower():
                    token_found = True
            if not token_found:
                print("[!!] Missing anti-CSRF token in POST form.")
                return True
        print("[-] Anti-CSRF token present or no POST forms.")
    except Exception as e:
        print(f"[!] CSRF Token Check Error: {str(e)}")
    return False

# === Origin & Referer Header Check ===
def check_origin_referer(url):
    print_progress("Checking Origin/Referer header behavior...")
    try:
        headers = {
            "Referer": "https://evil.com",
            "Origin": "https://evil.com"
        }
        response = requests.post(url, headers=headers, data={"test": "csrf"})
        if response.status_code in [200, 302]:
            print("[!!] Server accepts cross-origin requests without validation.")
            return True
        print("[-] Server validates Origin/Referer headers.")
    except Exception as e:
        print(f"[!] Origin/Referer Check Error: {str(e)}")
    return False

# === Main Function ===
def csrf_checker(url: str):
    url = url.strip()
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    print_progress(f"Scanning {url} for CSRF vulnerabilities...\n")

    get_csrf = check_get_csrf(url)
    post_csrf = check_post_csrf(url)
    json_csrf = check_json_csrf(url)
    token_missing = check_csrf_token(url)
    origin_check = check_origin_referer(url)

    is_vulnerable = any([get_csrf, post_csrf, json_csrf, token_missing, origin_check])

    results = {
        "vulnerable": is_vulnerable,
        "get_based": get_csrf,
        "post_based": post_csrf,
        "json_based": json_csrf,
        "token_missing": token_missing,
        "origin_validation_missing": origin_check
    }

    return results
