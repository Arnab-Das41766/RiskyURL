import requests
from urllib.parse import urljoin

def check_directory_fuzzing(url):
    print(f"[+] Checking for sensitive directories on {url}...")
    
    # Common sensitive paths to check
    sensitive_paths = [
        "admin", "admin/", "administrator", "login", "dashboard",
        ".env", ".git", ".git/config", ".svn",
        "config.php", "wp-config.php", "db_backup.sql",
        "backup", "backups", "test", "tmp",
        "robots.txt", "sitemap.xml"
    ]
    
    found_paths = []
    
    # Ensure URL ends with / for joining if it's a root domain, but urljoin handles it mostly.
    # Actually urljoin("http://example.com", "admin") -> "http://example.com/admin"
    
    for path in sensitive_paths:
        target_url = urljoin(url if url.endswith('/') else url + '/', path)
        try:
            response = requests.get(target_url, timeout=3, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                print(f"[!] Found: {target_url} (Status: {response.status_code})")
                found_paths.append(f"{target_url} ({response.status_code})")
        except requests.RequestException:
            continue

    is_vulnerable = len(found_paths) > 0
    
    return {
        "vulnerable": is_vulnerable,
        "found_paths": found_paths
    }
