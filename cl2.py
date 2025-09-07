#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import base64
import urllib.request
import subprocess
import platform
import threading
import re

# ---------------- مسیر فایل‌ها ----------------
TEXT_NORMAL = "normal.txt"
TEXT_FINAL = "final.txt"

# ---------------- منابع ----------------
LINKS_RAW = [
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/tepo60.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/tepo70.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/tepo80.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/tepo90.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/ss.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/vless.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/h2.txt",
    "https://raw.githubusercontent.com/tepo18/sab-vip10/main/trojan.txt",
]

MAX_THREADS = 20
MAX_PING_MS = 1200

def fetch_lines(url):
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            lines = resp.read().decode(errors="ignore").splitlines()
            return [line.strip() for line in lines if line.strip()]
    except Exception as e:
        print(f"[ERROR] Cannot fetch {url}: {e}")
        return []

def unique_lines(lines):
    seen = set()
    result = []
    for line in lines:
        if line not in seen:
            result.append(line)
            seen.add(line)
    return result

def ping(host, count=1, timeout=1):
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        cmd = ["ping", param_count, str(count), param_timeout, str(timeout), host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        match = re.search(r'time[=<]\s*(\d+\.?\d*)', output)
        if match:
            return float(match.group(1))
    except:
        pass
    return float('inf')

def extract_address(config_line):
    try:
        if config_line.startswith("vmess://"):
            encoded = config_line.split("://", 1)[1].split("#")[0]
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += "=" * (4 - missing_padding)
            data = json.loads(base64.b64decode(encoded).decode('utf-8'))
            host = data.get("add") or data.get("address")
            port = int(data.get("port", 443))
            return host, port
        elif config_line.startswith("vless://") or config_line.startswith("trojan://"):
            match = re.match(r'^[^:]+://[^@]+@([^:]+):(\d+)', config_line)
            if match:
                host, port = match.group(1), int(match.group(2))
                return host, port
        elif config_line.startswith("hy2://") or config_line.startswith("hysteria2://"):
            match = re.match(r'^[^:]+://([^:]+):(\d+)', config_line)
            if match:
                host, port = match.group(1), int(match.group(2))
                return host, port
    except:
        pass
    return None, None

def process_ping(configs):
    results = []
    lock = threading.Lock()
    threads = []

    def worker(cfg_line):
        host, port = extract_address(cfg_line)
        if host:
            ping_time = ping(host)
            if ping_time < MAX_PING_MS:
                with lock:
                    results.append((cfg_line, ping_time))

    for line in configs:
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()
        if len(threads) >= MAX_THREADS:
            for th in threads: th.join()
            threads = []

    for t in threads: t.join()
    results.sort(key=lambda x: x[1])
    return [cfg for cfg, p in results]

def save_files(normal_lines, final_lines):
    with open(TEXT_NORMAL, "w", encoding="utf-8") as f:
        f.write("\n".join(normal_lines))
    with open(TEXT_FINAL, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

def update_all():
    print("[*] Fetching sources...")
    all_lines = []
    for link in LINKS_RAW:
        all_lines.extend(fetch_lines(link))
    print(f"[*] Total lines fetched: {len(all_lines)}")

    all_lines = unique_lines(all_lines)
    print("[*] Stage 1: First ping check (basic filtering)...")
    normal_lines = process_ping(all_lines)
    print(f"[INFO] Saved {len(normal_lines)} configs to {TEXT_NORMAL}")

    print("[*] Stage 2: Detailed ping stability check...")
    final_lines = process_ping(normal_lines)
    print(f"[INFO] Saved {len(final_lines)} configs to {TEXT_FINAL}")

    save_files(normal_lines, final_lines)
    print("[✅] Update complete.")

if __name__ == "__main__":
    print("[*] Starting advanced auto-updater with stable ping checks every 6 hours...")
    while True:
        start = time.time()
        update_all()
        elapsed = time.time() - start
        print(f"[*] Elapsed time: {elapsed:.2f}s. Next update in 6 hours.\n")
        time.sleep(6 * 3600)
