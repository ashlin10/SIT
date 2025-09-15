from paramiko import SSHClient, AutoAddPolicy
import time
import re
from typing import Optional, Callable, Dict, Any

# Helper to safely emit logs

def _emit_lines(text: str, log_fn: Optional[Callable[[str, str], None]] = None, icon: str = ""):
    if not log_fn:
        return
    for line in (text or "").splitlines():
        if line.strip():
            log_fn(line.strip(), icon)


def run_restore_backup_on_device(
    ip: str,
    ssh_port: int,
    username: str,
    device_password: str,
    base_url: str,
    device_label: Optional[str] = None,
    do_restore: bool = True,
    timeout: int = 1800,
    log_fn: Optional[Callable[[str, str], None]] = None,
) -> Dict[str, Any]:
    """
    Connects to an FTD device via SSH, downloads the latest backup tar for the given device from base_url,
    and optionally initiates a restore. Streams terminal-like logs through log_fn.

    Returns: {success: bool, file?: str, error?: str}
    """
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    start_time = time.time()
    label = (device_label or ip).split(":", 1)[0]
    try:
        if log_fn:
            log_fn(f"Connecting to {ip}:{ssh_port} as {username}", "🔌")
        client.connect(
            hostname=ip,
            username=username,
            password=device_password,
            port=int(ssh_port),
            look_for_keys=False,
            allow_agent=False,
            timeout=30,
        )
        if log_fn:
            log_fn("SSH connection established", "✅")

        chan = client.invoke_shell()
        time.sleep(1)
        if chan.recv_ready():
            _emit_lines(chan.recv(8192).decode(errors="ignore"), log_fn, "📄")

        def send(cmd: str, wait: float = 1.0) -> str:
            chan.send(cmd + "\n")
            time.sleep(wait)
            buf = ""
            while chan.recv_ready():
                chunk = chan.recv(8192).decode(errors="ignore")
                buf += chunk
            return buf

        def become_root() -> None:
            """Enter expert mode and escalate to root with sudo, reliably handling the password prompt."""
            # Enter expert shell
            _emit_lines(send("expert", 1.0), log_fn, "➡️")
            # Start sudo su and handle password if prompted
            chan.send("sudo su\n")
            buf = ""
            pw_sent = False
            attempts = 0
            got_root = False
            deadline = time.time() + 25
            while time.time() < deadline:
                time.sleep(0.2)
                if chan.recv_ready():
                    chunk = chan.recv(8192).decode(errors="ignore")
                    buf += chunk
                    # Emit any visible lines for transparency
                    _emit_lines(chunk, log_fn, "➡️")
                    # If sudo prompts for password, send it once
                    if re.search(r"(?mi)^Sorry, try again\.", buf):
                        # Next Password: will come again; allow re-send
                        pw_sent = False
                    if (not pw_sent) and re.search(r"(?mi)^Password:\s*$", buf):
                        attempts += 1
                        chan.send(device_password + "\n")
                        pw_sent = True
                        if attempts >= 3:
                            break
                    # Detect root prompt
                    if re.search(r"(?m)^root@.*[#:]", buf):
                        got_root = True
                        break
            if not got_root:
                # Final verification using whoami
                who = send("whoami", 0.8)
                if not re.search(r"\broot\b", who):
                    raise RuntimeError("Failed to become root (sudo su).")

        # Become root and prepare directory
        become_root()
        _emit_lines(send("cd /var/sf/backup", 0.8), log_fn, "➡️")
        _emit_lines(send("rm -f *.tar", 0.8), log_fn, "🧹")

        if not base_url or not re.match(r"^https?://", base_url.strip(), re.IGNORECASE):
            raise ValueError("Invalid base_url; must start with http:// or https://")

        # Try to discover a URL for the device tar
        safe_label = re.escape(label)
        discover_cmd = (
            f"URL=$(wget --spider -r -l1 -nd -e robots=off \"{base_url}\" 2>&1 | "
            f"grep -oiE 'https?://[^ ]*{safe_label}[^ ]*\\.tar' | head -n1); echo $URL"
        )
        _emit_lines(f"Finding backup for {label} under {base_url}", log_fn, "🔎")

        # Run the search command to pick the device-specific backup and print its output
        if log_fn:
            log_fn(f"Search command: {discover_cmd}", "🧾")
        out = send(discover_cmd, 6.0)
        _emit_lines(out, log_fn, "")
        url = None
        m = re.search(r"(https?://[^\s]+\.tar)", out)
        if m:
            url = m.group(1)
            if log_fn:
                log_fn(f"Found URL: {url}", "✅")
        if not url:
            # Fallback: first .tar under base_url using spider output
            fallback_cmd = (
                f"URL=$(wget --spider -r -l1 -nd -e robots=off \"{base_url}\" 2>&1 | "
                f"grep -oiE 'https?://[^ ]*\\.tar' | head -n1); echo $URL"
            )
            if log_fn:
                log_fn(f"Fallback search command: {fallback_cmd}", "🧾")
            out = send(fallback_cmd, 6.0)
            _emit_lines(out, log_fn, "")
            m = re.search(r"(https?://[^\s]+\.tar)", out)
            if m:
                url = m.group(1)
                if log_fn:
                    log_fn(f"Fallback found URL: {url}", "✅")
        if not url:
            # HTML or plain-text directory listing fallback; handle relative and absolute links and label variations
            html = send(f"wget -qO- \"{base_url}\"", 6.0)
            # Try anchor-based listings first
            links = re.findall(r'href=["\']([^"\']+\\.tar)["\']', html, flags=re.IGNORECASE)
            if not links:
                # Plain text fallback: any whitespace-delimited token ending in .tar
                pt_matches = re.findall(r'(^|\s)([^\s]+\.tar)($|\s)', html, flags=re.IGNORECASE)
                links = [m[1] for m in pt_matches]
            if links:
                def make_abs(u: str) -> str:
                    if re.match(r'^https?://', u, re.IGNORECASE):
                        return u
                    return base_url.rstrip('/') + '/' + u.lstrip('/')
                norm_label = re.sub(r'[^A-Za-z0-9]', '', label or '').lower()
                scored = []
                for u in links:
                    absu = make_abs(u)
                    bn = absu.rsplit('/', 1)[-1]
                    norm_bn = re.sub(r'[^A-Za-z0-9]', '', bn).lower()
                    score = 1 if (norm_label and norm_label in norm_bn) else 0
                    scored.append((score, absu))
                scored.sort(reverse=True)
                url = scored[0][1]
        if not url:
            raise RuntimeError("Could not find any .tar backup URL from base_url")
        file_name = url.rsplit("/", 1)[-1]
        file_name = url.rsplit("/", 1)[-1]
        if log_fn:
            log_fn(f"Downloading: {file_name}", "⬇️")

        # Run wget and stream its output
        chan.send(f"wget -c {url}\n")
        buffer = ""
        last_emit = time.time()
        # Read until we get back to a prompt-like line or a long idle
        while True:
            time.sleep(1)
            try:
                if chan.recv_ready():
                    chunk = chan.recv(8192).decode(errors="ignore")
                    buffer += chunk
                    # emit lines incrementally
                    for line in chunk.splitlines():
                        if log_fn and line.strip():
                            log_fn(line.strip(), "")
                    last_emit = time.time()
                    # Break if we detect completion keywords
                    if re.search(r"100%|saved\s+\[|FINISHED|Downloaded", buffer, re.IGNORECASE):
                        # small grace to flush
                        time.sleep(0.8)
                        while chan.recv_ready():
                            extra = chan.recv(8192).decode(errors="ignore")
                            buffer += extra
                            for line in extra.splitlines():
                                if log_fn and line.strip():
                                    log_fn(line.strip(), "")
                        break
                # Timeout safeguard for very long inactivity
                if time.time() - last_emit > timeout:
                    raise TimeoutError("Download timed out")
            except Exception:
                break

        # Verify file exists and capture the newest tar filename on-box
        out = send(f"ls -1t /var/sf/backup/*.tar 2>/dev/null | head -1", 1.0)
        m_latest = re.search(r"/var/sf/backup/([^\s]+\.tar)", out)
        latest_base = m_latest.group(1) if m_latest else file_name
        if not m_latest and not re.search(r"\.tar", out):
            # Fallback quick check in cwd just in case
            alt = send(f"ls -1 {label}*.tar 2>/dev/null || ls -1 *.tar 2>/dev/null", 0.8)
            if file_name not in alt and not re.search(r"\.tar", alt):
                raise RuntimeError("Download failed or file not found")
        if log_fn:
            log_fn("Download completed", "✅")

        if do_restore:
            if log_fn:
                log_fn("Starting restore operation", "🚀")
            # Move back to clish before issuing restore command
            send("exit", 0.6)  # root -> admin
            send("exit", 0.8)  # admin -> clish
            # clish expects only the filename (not the full path)
            if log_fn:
                log_fn(f"Selected backup file: {file_name}", "📦")
                log_fn(f"Executing: restore remote-manager-backup {file_name}", "➡️")
            # Send without quotes as requested
            chan.send(f"restore remote-manager-backup {file_name}\n")

            restore_started = False
            start_restore_time = time.time()
            while True:
                time.sleep(2)
                if chan.recv_ready():
                    out = chan.recv(8192).decode(errors="ignore")
                    for line in out.splitlines():
                        if log_fn and line.strip():
                            log_fn(line.strip(), "📄")
                        if ("Are you sure you want to continue" in line) and not restore_started:
                            chan.send("Y\n")
                            restore_started = True
                    if (
                        "System will now reboot" in out
                        or "Connection closed" in out
                        or "The system is going down for reboot NOW" in out
                    ):
                        if log_fn:
                            log_fn("Restore initiated, device will reboot.", "🔄")
                        break
                # Hard timeout for restore loop
                if time.time() - start_restore_time > timeout:
                    if log_fn:
                        log_fn("Restore monitoring timed out; device may still be rebooting.", "⏰")
                    break

        try:
            client.close()
        except Exception:
            pass
        return {"success": True, "file": file_name}
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        if log_fn:
            log_fn(f"Error: {e}", "❌")
        return {"success": False, "error": str(e)}
