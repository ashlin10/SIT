import paramiko
import time
import threading
import concurrent.futures
import re
import os
import sys
import argparse

# Device map: hostname -> SSH port
devices = {
    # "wm-1": 12012,
    # "wm-2": 12013,
    # "wm-3": 12014,
    # "wm-4": 12015,
    # "wm-5": 12016,
    # "wm-6": 12017,
    # "wm-7": 12027,
    # # "WM-8": 12056,
    # # "WM-9": 12057,
    # # # # "KP-4": 12021,
    # # # # "KP-5": 12004,
    "qw-1": 12031,
    "qw-2": 12032,
    # "qw-3": 12033,
    # "qw-4": 12051,
    # "tpk-1": 12054,
    # "tpk-2": 12055,
    # "TPK-3": 12018,
    # "TPK-4": 12019,
    # "TPK-5": 12020,
    # "TPK-6": 12030,
    # "TPK-3-1": 12118,
    # "TPK-3-2": 12218,
    # "TPK-3-3": 12318,
    # "TPK-4-1": 12119,
    # "TPK-4-2": 12219,
    # "TPK-4-3": 12319
    # "VIC-1": 12003,
    # "VIC-2": 12065,
    # "vFTD-116": 12116
}

# SSH credentials (loaded from environment variables)
ssh_ip = os.environ.get("DEFAULT_HOST", "")
username = os.environ.get("DEFAULT_SSH_USERNAME", "")
password = os.environ.get("DEFAULT_FTD_PASSWORD", "")

# Backup file location URL
base_url = "http://u32-scratch.cisco.com/scratch/aleroyds/761-fmc-102-backup/sf-storage/09a90488-e182-11ec-8092-cfad964ea8e1/remote-backups/"

# Lock for thread-safe printing
print_lock = threading.Lock()

def log(msg):
    with print_lock:
        print(msg)

def send_command(shell, cmd, wait=1.5):
    shell.send(cmd + "\n")
    time.sleep(wait)
    return shell.recv(9999).decode()

# Shared progress dictionary and lock
progress_dict = {}
progress_lock = threading.Lock()

def log_progress(device_name, file_name, percent):
    with progress_lock:
        progress_dict[device_name] = f"[{device_name}] {file_name} Download Progress: {percent}%"
        # Move cursor up for all devices and overwrite lines
        sys.stdout.write('\033[F' * (len(progress_dict)))
        for dev in sorted(progress_dict):
            sys.stdout.write('\r' + progress_dict[dev] + ' ' * 20 + '\n')
        sys.stdout.flush()

def process_device(device_name, port, do_restore=False):
    log(f"[{device_name}] Connecting to {ssh_ip}:{port}...")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ssh_ip, port=port, username=username, password=password, look_for_keys=False)
        log(f"[{device_name}] ✅ SSH connection successful")

        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(9999)

        send_command(shell, "expert")
        send_command(shell, "sudo su")
        send_command(shell, password)
        send_command(shell, "cd /var/sf/backup")
        send_command(shell, "rm -f *.tar")
        log(f"[{device_name}] 🧹 Old backups deleted")

        # Find the URL for this device's backup
        # Prefer case-insensitive extended regex and boundary-aware matching so tpk-1-app1 doesn't match tpk-1-app10
        # Accept underscore/dash/dot or end after label
        shell.send(
            f'''URL=$(wget --spider -r -l1 -nd -e robots=off "{base_url}" 2>&1 | grep -oiE 'https?://[^ ]*{re.escape(device_name)}([_\.-]|$)[^ ]*\\.tar' | head -n1); echo $URL\n'''
        )
        time.sleep(2)
        output = shell.recv(9999).decode()
        url_match = re.search(r'(https?://[^\s]+\.tar)', output)
        if not url_match:
            # Simple HTML directory listing fallback
            shell.send(f"wget -qO- \"{base_url}\"\n")
            time.sleep(3)
            html = shell.recv(9999).decode(errors="ignore")
            links = re.findall(r'href=["\']([^"\']+\.tar)["\']', html, flags=re.IGNORECASE)
            if not links:
                # Plain text tokens fallback
                links = [m[1] for m in re.findall(r'(^|\s)([^\s]+\.tar)($|\s)', html, flags=re.IGNORECASE)]
            def make_abs(u: str) -> str:
                return u if re.match(r'^https?://', u, re.IGNORECASE) else base_url.rstrip('/') + '/' + u.lstrip('/')
            # Score links; prefer boundary match right after device name
            label_esc = re.escape(device_name)
            p_strong = re.compile(rf'(^|[_\-/]){label_esc}([_\-/\.]|$)', re.IGNORECASE)
            p_weak = re.compile(rf'{label_esc}', re.IGNORECASE)
            scored = []
            for u in links:
                absu = make_abs(u)
                bn = absu.rsplit('/', 1)[-1]
                score = 100 if p_strong.search(bn) else (10 if p_weak.search(bn) else 0)
                scored.append((score, absu))
            scored.sort(reverse=True)
            if scored and scored[0][0] > 0:
                url = scored[0][1]
                file_name = os.path.basename(url)
                log(f"[{device_name}] ⬇️ Downloading: {file_name}")
            else:
                log(f"[{device_name}] ❌ Could not find backup URL in output.")
                send_command(shell, "exit")
                send_command(shell, "exit")
                client.close()
                return
        else:
            url = url_match.group(1)
            file_name = os.path.basename(url)
            log(f"[{device_name}] ⬇️ Downloading: {file_name}")

        # Start the wget download and monitor progress
        shell.send(f"wget {url}\n")
        percent = 0
        buffer = ""
        last_percent = -1
        while percent < 100:
            time.sleep(1)
            if shell.recv_ready():
                chunk = shell.recv(4096).decode(errors="ignore")
                buffer += chunk
                percents = re.findall(r'(\d{1,3})%', buffer)
                if percents:
                    percent = int(percents[-1])
                    if percent != last_percent:
                        log_progress(device_name, file_name, percent)
                        last_percent = percent
            if re.search(r'# $', buffer) or re.search(r'\$ $', buffer):
                break
        log_progress(device_name, file_name, 100)  # Ensure 100% is shown at the end

        # Check if file exists (find any .tar file for this device)
        result = send_command(shell, f"ls {device_name}*.tar")
        if f"{device_name}" in result and ".tar" in result:
            log(f"[{device_name}] ✅ Download completed")
        else:
            log(f"[{device_name}] ❌ Download failed or file not found")
            send_command(shell, "exit")
            send_command(shell, "exit")
            client.close()
            return

        if do_restore:
            # Exit to admin and then to FTD CLI prompt
            send_command(shell, "exit")  # from root to admin
            send_command(shell, "exit")  # from admin to FTD CLI (>)

            # Start restore
            restore_cmd = f"restore remote-manager-backup {file_name}"
            log(f"[{device_name}] 🚀 Starting restore: {restore_cmd}")
            shell.send(restore_cmd + "\n")

            # Wait for the confirmation prompt and send 'Y'
            restore_started = False
            last_line = ""
            while True:
                time.sleep(2)
                if shell.recv_ready():
                    output = shell.recv(4096).decode(errors="ignore")
                    lines = output.strip().splitlines()
                    if lines:
                        last_line = lines[-1]
                        # Print only the last line
                        with print_lock:
                            print(f"[{device_name}] {last_line}{' ' * 20}")
                        # Look for confirmation prompt
                        if "Are you sure you want to continue" in last_line and not restore_started:
                            shell.send("Y\n")
                            restore_started = True
                    # Detect reboot or session close
                    if (
                        "System will now reboot" in output
                        or "Connection closed" in output
                        or "The system is going down for reboot NOW" in output
                    ):
                        break

            log(f"[{device_name}] 🔄 Restore initiated, device will reboot.")

        client.close()

    except Exception as e:
        log(f"[{device_name}] ❌ SSH connection or command failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Download and optionally restore FTD backups.")
    parser.add_argument("--restore", action="store_true", help="Restore the backup after download")
    args = parser.parse_args()

    log("🔄 Starting parallel backup download for FTDs...\n")
    # Print empty progress lines for each device to reserve space
    for device in devices:
        print(f"[{device}] ...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(devices)) as executor:
        futures = [executor.submit(process_device, device, port, args.restore) for device, port in devices.items()]
        concurrent.futures.wait(futures)
    log("\n✅ All operations completed.")

if __name__ == "__main__":
    main()
