#!/usr/bin/env python3
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRITERION_DIR = ROOT / "target" / "criterion"

BENCHES = [
    "user.request",
    "user.handle_response",
    "user.update_request",
    "user.handle_update_response",
    "user.submit_request",
    "user.handle_submit_response",
    "server.open_registration",
    "server.handle_submit",
    "server.handle_update",
]

NS_TO_MS = 1e-6


def read_est(name: str):
    path = CRITERION_DIR / name / "new" / "estimates.json"
    data = json.loads(path.read_text())
    mean = data["mean"]["point_estimate"]
    std_dev = data["std_dev"]["point_estimate"]
    return mean, std_dev


def sum_stats(a, b):
    mean = a[0] + b[0]
    std_dev = math.sqrt(a[1] ** 2 + b[1] ** 2)
    return mean, std_dev


def fmt_ms(value_ms: float) -> str:
    return f"{value_ms:.2f}"


def main():
    vals = {b: read_est(b) for b in BENCHES}

    client_reg = sum_stats(vals["user.request"], vals["user.handle_response"])
    client_submit = sum_stats(vals["user.submit_request"], vals["user.handle_submit_response"])
    client_update = sum_stats(vals["user.update_request"], vals["user.handle_update_response"])

    server_reg = vals["server.open_registration"]
    server_submit = vals["server.handle_submit"]
    server_update = vals["server.handle_update"]

    rows = [
        ("client_reg", client_reg),
        ("client_submit", client_submit),
        ("client_update", client_update),
        ("server_reg", server_reg),
        ("server_submit", server_submit),
        ("server_update", server_update),
    ]

    for label, (mean_ns, std_ns) in rows:
        mean_ms = mean_ns * NS_TO_MS
        std_ms = std_ns * NS_TO_MS
        print(label, fmt_ms(mean_ms), fmt_ms(std_ms))


if __name__ == "__main__":
    main()
