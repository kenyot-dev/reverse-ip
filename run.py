import json
import random
import time
import ipaddress
from pathlib import Path
import requests
from colorama import Fore, Style, init

init(autoreset=True)


BASE = Path(__file__).resolve().parent
API_URL = "https://api.dnsrift.net/reverse-ip-lookup"

TARGET_FILE = BASE / "target.txt"
PROXY_FILE = BASE / "proxy.txt"
UA_FILE = BASE / "ua.json"

OUTPUT_DIR = BASE / "results"
DOMAIN_FILE = OUTPUT_DIR / "domain.txt"

TIMEOUT = 30
DELAY = 1

C = Fore.CYAN
G = Fore.GREEN
Y = Fore.YELLOW
R = Fore.RED
RESET = Style.RESET_ALL


def read_lines(path):
    if not path.exists():
        return []

    return [
        line.strip()
        for line in path.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def load_targets():
    targets = []
    seen = set()

    for value in read_lines(TARGET_FILE):
        try:
            ip = ipaddress.ip_address(value)

            if not ip.is_global:
                print(f"{Y}[SKIP] IP: {value}{RESET}")
                continue

            value = str(ip)

            if value not in seen:
                seen.add(value)
                targets.append(value)

        except ValueError:
            print(f"{Y}[SKIP] bukan IP tunggal: {value}{RESET}")

    return targets


def load_user_agents():
    try:
        data = json.loads(UA_FILE.read_text(encoding="utf-8"))

        if isinstance(data, dict):
            data = data.get("user_agents", [])

        if not isinstance(data, list):
            raise ValueError("Format ua.json harus berupa array")

        agents = [
            str(item).strip()
            for item in data
            if str(item).strip()
        ]

        if agents:
            return agents

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"{Y}[WARN] Gagal membaca ua.json: {exc}{RESET}")

    return [
        "Mozilla/5.0 (Linux; Android 15) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/130.0.0.0 Mobile Safari/537.36"
    ]


def load_proxies():
    proxies = []

    for value in read_lines(PROXY_FILE):
        if "://" not in value:
            value = "http://" + value

        scheme = value.split("://", 1)[0].lower()

        if scheme not in (
            "http", "https",
            "socks4", "socks4a",
            "socks5", "socks5h"
        ):
            print(f"{Y}[SKIP] Skema proxy invalid: {value}{RESET}")
            continue

        if value not in proxies:
            proxies.append(value)

    return proxies

def load_saved_domains():
    if not DOMAIN_FILE.exists():
        return set()

    return {
        line.strip().lower()
        for line in DOMAIN_FILE.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()
        if line.strip()
    }


def save_new_domains(domains, saved_domains):
    new_domains = []

    for item in domains:
        domain = str(item).strip()

        if not domain:
            continue

        key = domain.lower()

        if key not in saved_domains:
            saved_domains.add(key)
            new_domains.append(domain)

    if new_domains:
        with DOMAIN_FILE.open("a", encoding="utf-8") as file:
            for domain in new_domains:
                file.write(domain + "\n")

    return len(new_domains)


def lookup_ip(ip, agents, proxies, proxy_start):
    headers = {
        "User-Agent": random.choice(agents),
        "Accept": "application/json",
    }


    if not proxies:
        candidates = [None]
    else:
        candidates = [
            (proxy_start + offset) % len(proxies)
            for offset in range(len(proxies))
        ]

    last_error = "Semua percobaan koneksi gagal"

    for candidate in candidates:
        proxy_url = (
            proxies[candidate]
            if candidate is not None
            else None
        )

        request_options = {
            "headers": headers,
            "timeout": TIMEOUT,
        }

        if proxy_url:
            request_options["proxies"] = {
                "http": proxy_url,
                "https": proxy_url,
            }

        try:
            response = requests.get(
                API_URL,
                params={"ip": ip},
                **request_options
            )

            if response.status_code == 429:
                return response, candidate, "rate_limit"
            if (
                proxy_url
                and response.status_code in (502, 503, 504)
            ):
                last_error = f"HTTP {response.status_code}"
                print(
                    f"{Y}[PROXY] {proxy_url} -> {last_error}; "
                    f"next{RESET}"
                )
                continue

            return response, candidate, None

        except requests.RequestException as exc:
            last_error = str(exc)

            label = proxy_url or "koneksi langsung"

            print(
                f"{Y}[PROXY] {label} gagal: "
                f"{last_error[:140]}{RESET}"
            )

            continue

    return None, None, last_error


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    targets = load_targets()
    agents = load_user_agents()
    proxies = load_proxies()
    saved_domains = load_saved_domains()

    if not targets:
        print(f"{R}[ERROR] target.txt kosong{RESET}")
        return


    processed = 0
    new_total = 0
    errors = 0
    proxy_index = 0

    for index, ip in enumerate(targets, 1):
        response, used_index, error = lookup_ip(
            ip,
            agents,
            proxies,
            proxy_index
        )

        if used_index is not None and proxies:
            proxy_index = (used_index + 1) % len(proxies)

        if response is None:
            errors += 1
            print(
                f"{R}[{index}/{len(targets)}] ERROR "
                f"{ip}: {str(error)[:150]}{RESET}"
            )

        elif response.status_code == 429:
            print(f"{Y}[STOP] HTTP 429: rate limit tercapai.{RESET}")
            print("Proses dihentikan. Coba lagi setelah kuota tersedia.")
            break

        else:
            try:
                data = response.json()
            except ValueError:
                data = {}

            if response.status_code != 200:
                errors += 1
                print(
                    f"{R}[{index}/{len(targets)}] ERROR "
                    f"{ip}: HTTP {response.status_code} - "
                    f"{data.get('message', 'Respons tidak valid')}{RESET}"
                )

            elif data.get("error"):
                errors += 1
                print(
                    f"{R}[{index}/{len(targets)}] ERROR "
                    f"{ip}: {data.get('message', data['error'])}{RESET}"
                )

            else:
                domains = data.get("domain_list", [])

                if not isinstance(domains, list):
                    domains = []

                added = save_new_domains(
                    domains,
                    saved_domains
                )

                processed += 1
                new_total += added

                route = (
                    proxies[used_index]
                    if used_index is not None and proxies
                    else "direct"
                )

                remaining = response.headers.get(
                    "X-RateLimit-Remaining", "?"
                )

                print(
                    f"{G}[{index}/{len(targets)}] {ip} > "
                    f"{len(domains)} hasil | "
                    f"{added} domain baru | "
                    f"total unik {len(saved_domains)} | "
                    f"kuota tersisa {remaining}{RESET}"
                )

        if index < len(targets):
            time.sleep(DELAY)

    print(f"\n{C}Selesai{RESET}")
    print(f"IP berhasil diproses: {processed}")
    print(f"Domain baru ditambahkan: {new_total}")
    print(f"Error: {errors}")
    print(f"Total domain unik: {len(saved_domains)}")
    print(f"File domain: {DOMAIN_FILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nMarian.")
