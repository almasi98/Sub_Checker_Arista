#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, time, threading, urllib.request, base64, json, subprocess, platform, re

# ---------------- مسیر فایل‌ها ----------------
NORMAL_FILE = "normal.txt"
FINAL_FILE = "final.txt"
RAW_HEADER = "//profile-title: base64:2YfZhduM2LTZhyDZgdi52KfZhCDwn5iO8J+YjvCfmI4gaGFtZWRwNzE="

# ---------------- منابع ----------------
SOURCES = [
    "https://raw.githubusercontent.com/almasi98/omax98/main/h2.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/vless.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/ss.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/vmess.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/trojan.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/tepo10.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/tepo20.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/tepo30.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/tepo40.txt",
    "https://raw.githubusercontent.com/almasi98/omax98/main/tepo50.txt",
    
]

MAX_THREADS = 20
PING_THRESHOLD = 1200  # میلی‌ثانیه

# ---------------- تابع خواندن منابع ----------------
def fetch_sources():
    all_lines = []
    for url in SOURCES:
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                text = resp.read().decode(errors="ignore")
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                all_lines.extend(lines)
                print(f"[INFO] Fetched {len(lines)} lines from {url}")
        except Exception as e:
            print(f"[ERROR] Cannot fetch {url}: {e}")
    return list(set(all_lines))  # حذف تکراری اولیه

# ---------------- تابع پینگ ----------------
def ping_address(address):
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        cmd = ["ping", param_count, "1", param_timeout, "1", address]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        match = re.search(r'time[=<]\s*(\d+\.?\d*)', output)
        if match:
            return float(match.group(1))
    except:
        pass
    return float('inf')

# ---------------- استخراج آدرس از کانفیگ ----------------
def extract_address(config_line):
    # اینجا فقط برای vmess، vless و hy2 ساده نمونه
    if config_line.startswith("vmess://"):
        try:
            encoded = config_line[8:]
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += "=" * (4 - missing_padding)
            data = json.loads(base64.b64decode(encoded).decode())
            address = data.get("add")
            return address
        except:
            return None
    # برای hy2 یا بقیه پروتکل‌ها می‌توان همین‌طور افزود
    return None

# ---------------- تست پینگ و فیلتر ----------------
def check_ping(lines):
    results = []
    lock = threading.Lock()
    threads = []

    def worker(line):
        addr = extract_address(line)
        if addr:
            t = ping_address(addr)
            if t < float('inf'):
                with lock:
                    results.append((line, t))

    for line in lines:
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()
        if len(threads) >= MAX_THREADS:
            for th in threads: th.join()
            threads = []

    for th in threads:
        th.join()

    # حذف تکراری‌ها و کانفیگ‌های مشکل دار
    unique = {}
    for line, t in results:
        if line not in unique:
            unique[line] = t
    return unique

# ---------------- ذخیره فایل ----------------
def save_file(filename, lines):
    with open(filename, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")
    print(f"[INFO] Saved {len(lines)} lines to {filename}")

# ---------------- بروزرسانی اصلی ----------------
def update_all():
    print("[*] Fetching sources...")
    lines = fetch_sources()
    print(f"[*] Total lines fetched: {len(lines)}")

    print("[*] Stage 1: First ping check (normal.txt)...")
    stage1 = check_ping(lines)
    save_file(NORMAL_FILE, stage1.keys())

    print("[*] Stage 2: Detailed ping stability check (final.txt)...")
    # فقط کانفیگ‌های پایدار با پینگ ≤ PING_THRESHOLD
    stage2 = {line: t for line, t in stage1.items() if t <= PING_THRESHOLD}
    save_file(FINAL_FILE, stage2.keys())

    print(f"[✅] Update complete. {len(stage2)} configs in final.txt")

# ---------------- Main Loop ----------------
if __name__ == "__main__":
    print("[*] Starting auto-updater with stable ping checks...")
    while True:
        start = time.time()
        update_all()
        elapsed = time.time() - start
        print(f"[*] Next update in 1 hour. Elapsed: {elapsed:.2f}s\n")
        time.sleep(3600)#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, time, threading, urllib.request, base64, json, subprocess, platform, re

# ---------------- مسیر فایل‌ها ----------------
NORMAL_FILE = "normal.txt"
FINAL_FILE = "final.txt"
RAW_HEADER = "//profile-title: base64:2YfZhduM2LTZhyDZgdi52KfZhCDwn5iO8J+YjvCfmI4gaGFtZWRwNzE="

# ---------------- منابع ----------------
SOURCES = [
    
]

MAX_THREADS = 20
PING_THRESHOLD = 1200  # میلی‌ثانیه

# ---------------- تابع خواندن منابع ----------------
def fetch_sources():
    all_lines = []
    for url in SOURCES:
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                text = resp.read().decode(errors="ignore")
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                all_lines.extend(lines)
                print(f"[INFO] Fetched {len(lines)} lines from {url}")
        except Exception as e:
            print(f"[ERROR] Cannot fetch {url}: {e}")
    return list(set(all_lines))  # حذف تکراری اولیه

# ---------------- تابع پینگ ----------------
def ping_address(address):
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        cmd = ["ping", param_count, "1", param_timeout, "1", address]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        match = re.search(r'time[=<]\s*(\d+\.?\d*)', output)
        if match:
            return float(match.group(1))
    except:
        pass
    return float('inf')

# ---------------- استخراج آدرس از کانفیگ ----------------
def extract_address(config_line):
    # اینجا فقط برای vmess، vless و hy2 ساده نمونه
    if config_line.startswith("vmess://"):
        try:
            encoded = config_line[8:]
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += "=" * (4 - missing_padding)
            data = json.loads(base64.b64decode(encoded).decode())
            address = data.get("add")
            return address
        except:
            return None
    # برای hy2 یا بقیه پروتکل‌ها می‌توان همین‌طور افزود
    return None

# ---------------- تست پینگ و فیلتر ----------------
def check_ping(lines):
    results = []
    lock = threading.Lock()
    threads = []

    def worker(line):
        addr = extract_address(line)
        if addr:
            t = ping_address(addr)
            if t < float('inf'):
                with lock:
                    results.append((line, t))

    for line in lines:
        t = threading.Thread(target=worker, args=(line,))
        threads.append(t)
        t.start()
        if len(threads) >= MAX_THREADS:
            for th in threads: th.join()
            threads = []

    for th in threads:
        th.join()

    # حذف تکراری‌ها و کانفیگ‌های مشکل دار
    unique = {}
    for line, t in results:
        if line not in unique:
            unique[line] = t
    return unique

# ---------------- ذخیره فایل ----------------
def save_file(filename, lines):
    with open(filename, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")
    print(f"[INFO] Saved {len(lines)} lines to {filename}")

# ---------------- بروزرسانی اصلی ----------------
def update_all():
    print("[*] Fetching sources...")
    lines = fetch_sources()
    print(f"[*] Total lines fetched: {len(lines)}")

    print("[*] Stage 1: First ping check (normal.txt)...")
    stage1 = check_ping(lines)
    save_file(NORMAL_FILE, stage1.keys())

    print("[*] Stage 2: Detailed ping stability check (final.txt)...")
    # فقط کانفیگ‌های پایدار با پینگ ≤ PING_THRESHOLD
    stage2 = {line: t for line, t in stage1.items() if t <= PING_THRESHOLD}
    save_file(FINAL_FILE, stage2.keys())

    print(f"[✅] Update complete. {len(stage2)} configs in final.txt")

# ---------------- Main Loop ----------------
if __name__ == "__main__":
    print("[*] Starting auto-updater with stable ping checks...")
    while True:
        start = time.time()
        update_all()
        elapsed = time.time() - start
        print(f"[*] Next update in 1 hour. Elapsed: {elapsed:.2f}s\n")
        time.sleep(3600)
