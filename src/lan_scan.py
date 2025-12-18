#!/usr/bin/env python3
"""
Aktiver LAN-Scanner fuer OctoPrint-, Klipper- und Elegoo-Centurio-Installationen.
Scant IPv4-Netze auf typische Ports und gibt gefundene Hosts aus.
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Dict, Iterable, List, Mapping, Sequence

# Bekannte Ziele und ihre typischen Ports/Signaturen.
TARGETS = {
    "OctoPrint": {
        "ports": {80, 443, 5000},
        # Starke Indikatoren, auch ohne HTTP-Text
        "strong_ports": {5000},
        "http_keywords": ("octoprint",),
    },
    "Klipper": {
        "ports": {80, 443, 8080, 7125},
        "strong_ports": {7125},
        "http_keywords": ("moonraker", "klipper", "mainsail", "fluidd"),
    },
    "Elegoo Centurio": {
        # Centurio Carbon spricht ueber Moonraker/Fluidd, teilt daher Ports mit Klipper
        "ports": {80, 443, 8080, 7125},
        "strong_ports": {7125},
        "http_keywords": ("elegoo", "centurio", "moonraker", "fluidd"),
    },
}

UNIQUE_PORTS = sorted({p for cfg in TARGETS.values() for p in cfg["ports"]})
HTTP_PORTS = {80, 443, 5000, 7125, 8080}


def guess_network(default_cidr: str = "192.168.0.0/24") -> ipaddress.IPv4Network:
    """Versucht, das lokale /24-Netz anhand der aktiven IP zu raten."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
    except OSError:
        return ipaddress.ip_network(default_cidr, strict=False)

    octets = local_ip.split(".")
    if len(octets) != 4 or local_ip.startswith("127."):
        return ipaddress.ip_network(default_cidr, strict=False)

    cidr = ".".join(octets[:3]) + ".0/24"
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return ipaddress.ip_network(default_cidr, strict=False)


def is_port_open(ip: str, port: int, timeout: float) -> bool:
    """Prueft, ob ein Port via TCP erreichbar ist."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def read_http_banner(ip: str, port: int, timeout: float) -> str:
    """Holt einen kurzen HTTP-Banner fuer die Erkennung."""
    request = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()

    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            if port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                    tls_sock.sendall(request)
                    return tls_sock.recv(2048).decode(errors="ignore").lower()

            raw_sock.sendall(request)
            return raw_sock.recv(2048).decode(errors="ignore").lower()
    except (OSError, ssl.SSLError):
        return ""


def classify(ip: str, open_port: int, banner: str) -> Mapping[str, List[int]]:
    """Ordnet geoeffnete Ports OctoPrint/Klipper zu."""
    found: Dict[str, List[int]] = {}
    for name, cfg in TARGETS.items():
        if open_port not in cfg["ports"]:
            continue
        if open_port in cfg["strong_ports"]:
            found.setdefault(name, []).append(open_port)
            continue
        if banner and any(keyword in banner for keyword in cfg["http_keywords"]):
            found.setdefault(name, []).append(open_port)
    return found


def probe_host(ip: str, timeout: float) -> Mapping[str, List[int]]:
    """Scant einen Host ueber alle bekannten Ports."""
    matches: Dict[str, List[int]] = {}
    for port in UNIQUE_PORTS:
        if not is_port_open(ip, port, timeout):
            continue
        banner = read_http_banner(ip, port, timeout) if port in HTTP_PORTS else ""
        for name, ports in classify(ip, port, banner).items():
            matches.setdefault(name, []).extend(ports)
    return matches


def scan_network(
    network: ipaddress.IPv4Network, timeout: float, workers: int
) -> Mapping[str, Dict[str, List[int]]]:
    """Scannt ein Netz parallel und sammelt Treffer."""
    hits: Dict[str, Dict[str, List[int]]] = {name: {} for name in TARGETS}
    addresses: List[str] = [str(ip) for ip in network.hosts()]
    total = len(addresses)
    progress = 0
    lock = Lock()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(probe_host, ip, timeout): ip for ip in addresses
        }
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                result = future.result()
            except Exception:
                continue

            for name, ports in result.items():
                hits[name][ip] = sorted(set(ports))

            with lock:
                progress += 1
                render_progress(progress, total)

    return hits


def print_summary(found: Mapping[str, Dict[str, List[int]]]) -> None:
    """Gibt gefundene IPs je Dienst aus."""
    any_hits = False
    for name in TARGETS:
        service_hits = found.get(name, {})
        if not service_hits:
            continue
        any_hits = True
        print(f"{name}:")
        for ip in sorted(service_hits):
            port_list = ", ".join(str(p) for p in service_hits[ip])
            print(f"  {ip} (Ports: {port_list})")

    if not any_hits:
        print("Keine OctoPrint- oder Klipper-Hosts gefunden.")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aktiver OctoPrint/Klipper LAN-Scanner."
    )
    parser.add_argument(
        "--cidr",
        help="Optionales Netz in CIDR-Notation (z.B. 192.168.178.0/24). "
        "Ohne Angabe wird das lokale /24 geraten.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.6,
        help="Timeout pro Port (Sekunden).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=64,
        help="Parallelitaet (Threads) fuer den Scan.",
    )
    return parser.parse_args(argv)


def render_progress(done: int, total: int) -> None:
    """Gibt einen einfachen Fortschrittsbalken aus."""
    if total <= 0:
        return
    bar_len = 30
    pct = int((done / total) * 100)
    filled = int(bar_len * done / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\rFortschritt [{bar}] {done}/{total} ({pct}%)")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")


def main() -> None:
    args = parse_args()
    network = (
        ipaddress.ip_network(args.cidr, strict=False)
        if args.cidr
        else guess_network()
    )

    print(f"Scanne Netz {network} auf OctoPrint/Klipper ...")
    found = scan_network(network, timeout=args.timeout, workers=args.workers)
    print_summary(found)


if __name__ == "__main__":
    main()
