import os
import subprocess
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import hashlib

TARGET_DISK_IMAGE = "./disk_image.dd"  # Path to disk image for analysis
RECOVERED_FILES_DIR = "./recovered_files/"  # Directory to store recovered files
MALICIOUS_INDICATORS = ["cmd.exe", "powershell.exe", "suspicious_script.sh"]  # Known malicious files to detect

LOG_FILE = "forensics_log.txt"

log_handler = RotatingFileHandler(LOG_FILE, maxBytes=10**6, backupCount=3)
log_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(message)s')
log_handler.setFormatter(formatter)

logging.getLogger().addHandler(log_handler)
logging.getLogger().setLevel(logging.DEBUG)

def log_event(event):
    logging.info(event)
    print(f"[LOGGED]: {event}")

def recover_deleted_files(disk_image):
    print("[*] Recovering deleted files from disk image...")
    Path(RECOVERED_FILES_DIR).mkdir(parents=True, exist_ok=True)

    if not Path(disk_image).exists():
        log_event(f"Disk image {disk_image} not found.")
        print("[!] Disk image not found.")
        return

    try:
        command = ["foremost", "-i", disk_image, "-o", RECOVERED_FILES_DIR]
        subprocess.run(command, check=True)
        log_event("Recovered deleted files successfully.")
        print(f"[+] Files recovered to {RECOVERED_FILES_DIR}")
    except subprocess.CalledProcessError as e:
        log_event(f"File recovery failed: {e}")
        print("[!] File recovery failed.")

def analyze_malicious_artifacts(directory):
    print("[*] Analyzing recovered files for malicious artifacts...")
    suspicious_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            if any(indicator.lower() in file.lower() for indicator in MALICIOUS_INDICATORS):
                suspicious_files.append(os.path.join(root, file))

    if suspicious_files:
        log_event(f"Suspicious files detected: {suspicious_files}")
        print(f"[+] Suspicious files found: {suspicious_files}")
    else:
        print("[!] No suspicious files detected.")

def extract_metadata(file_path):
    print(f"[*] Extracting metadata from {file_path}...")

    if not Path(file_path).exists():
        log_event(f"File {file_path} not found.")
        print("[!] File not found.")
        return

    try:
        command = ["exiftool", file_path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        metadata = result.stdout
        log_event(f"Extracted metadata from {file_path}:\n{metadata}")
        print(metadata)
    except subprocess.CalledProcessError as e:
        log_event(f"Metadata extraction failed: {e}")
        print("[!] Metadata extraction failed.")

def extract_system_info():
    print("[*] Extracting system information...")
    try:
        # Example for Linux-based systems (extend this for other platforms)
        command = ["uname", "-a"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        sys_info = result.stdout
        log_event(f"Extracted system info:\n{sys_info}")
        print(sys_info)
    except subprocess.CalledProcessError as e:
        log_event(f"System info extraction failed: {e}")
        print("[!] System info extraction failed.")

def check_file_integrity(file_path):
    print(f"[*] Checking integrity of {file_path}...")
    if not Path(file_path).exists():
        log_event(f"File {file_path} not found.")
        print("[!] File not found.")
        return

    try:
        command = ["sha256sum", file_path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        file_hash = result.stdout.split()[0]
        log_event(f"File hash (SHA256) for {file_path}: {file_hash}")
        print(f"File hash (SHA256): {file_hash}")
    except subprocess.CalledProcessError as e:
        log_event(f"File integrity check failed: {e}")
        print("[!] File integrity check failed.")

def analyze_network_activity():
    print("[*] Analyzing network activity...")
    try:
        # Example for Unix-like systems (can be extended for Windows with `netstat` command)
        command = ["ss", "-tuln"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        network_info = result.stdout
        log_event(f"Network activity:\n{network_info}")
        print(network_info)
    except subprocess.CalledProcessError as e:
        log_event(f"Network activity analysis failed: {e}")
        print("[!] Network activity analysis failed.")

def analyze_file(file_path):
    print(f"[*] Analyzing file {file_path} for type/signature...")

    if not Path(file_path).exists():
        log_event(f"File {file_path} not found.")
        print("[!] File not found.")
        return

    try:
        command = ["file", "--mime-type", file_path]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        file_type = result.stdout.strip().split(":")[1].strip()
        log_event(f"File type for {file_path}: {file_type}")
        print(f"File type: {file_type}")
    except subprocess.CalledProcessError as e:
        log_event(f"File type analysis failed: {e}")
        print("[!] File type analysis failed.")

def process_files_in_parallel(file_paths, function_to_run, is_cpu_bound=False):
    executor_class = ProcessPoolExecutor if is_cpu_bound else ThreadPoolExecutor
    with executor_class() as executor:
        executor.map(function_to_run, file_paths)

if __name__ == "__main__":
    print("DIGITAL FORENSICS FRAMEWORK ACTIVATED")
    log_event("Forensics framework initialized.")
    
    recover_deleted_files(TARGET_DISK_IMAGE)
    
    analyze_malicious_artifacts(RECOVERED_FILES_DIR)
    
    recovered_files = list(Path(RECOVERED_FILES_DIR).rglob("*"))
    process_files_in_parallel(recovered_files, extract_metadata, is_cpu_bound=False)
    
    process_files_in_parallel(recovered_files, analyze_file, is_cpu_bound=True)
    
    extract_system_info()
    
    # Analyze network activity (only works on Unix-like systems)
    analyze_network_activity()
    
    process_files_in_parallel(recovered_files, check_file_integrity, is_cpu_bound=True)
    
    print("[+] Forensic analysis completed. Monetize the findings or uncover deeper truths.")