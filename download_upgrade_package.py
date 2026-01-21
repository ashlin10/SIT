import os
from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction
import re
from typing import List, Optional, Callable, Dict, Any

# Load from environment variables (no hardcoded credentials)
host1 = os.environ.get("DEFAULT_HOST", "")
username = os.environ.get("DEFAULT_SSH_USERNAME", "")
ftd_password = os.environ.get("DEFAULT_FTD_PASSWORD", "")
fmc_password = os.environ.get("DEFAULT_FMC_PASSWORD", "")
clish = "> "
expert = ".+\$\s+"
expert_root = ".+\#\s+"


dev_path = 'https://firepower-engfs-bgl.cisco.com/netboot/ims/Development'
rel_path = 'https://firepower-engfs-bgl.cisco.com/netboot/ims/Release'

def run_commands_over_ssh(host, port, password, commands, username_override: Optional[str] = None, log_fn: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    print(f"Connecting to FMC {host} on port {port}...")
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        # Connect to the provided host (from selected FMC), not the static host1
        client.connect(hostname=host, username=username_override or username, password=password, port=port)
        print(f"SSH connection established to FMC {host}")

        with SSHClientInteraction(client, timeout=1200, display=False) as interact:
            interact.expect(clish)
            for idx, cmd in enumerate(commands):
                if cmd.startswith("wget "):
                    # Extract filename for nicer progress messages
                    try:
                        file_name = cmd.split('/')[-1].strip()
                    except Exception:
                        file_name = cmd.replace('wget', '').strip()
                    if log_fn:
                        log_fn(f"Downloading: {file_name}", "⬇️")
                    else:
                        print(f"{'#'*10} Downloading: {file_name} {'#'*10}")
                    interact.send(cmd)
                    percent = 0
                    last_percent = -1
                    while percent < 100:
                        output = interact.expect([r'(\d{1,3})%', expert_root], timeout=600)
                        if interact.last_match == expert_root:
                            if log_fn:
                                log_fn("Download complete.", "✅")
                            else:
                                print("Download complete.")
                            break
                        match = re.search(r'(\d{1,3})%', interact.current_output)
                        if match:
                            percent = int(match.group(1))
                            if percent != last_percent:
                                last_percent = percent
                                if log_fn:
                                    log_fn(f"{file_name} {percent}%", "📈")
                                else:
                                    print(f"\r{file_name} {percent}%", end="", flush=True)
                    if not log_fn:
                        print("\n")
                    # Ensure final 100% is shown in logs
                    if last_percent < 100:
                        if log_fn:
                            log_fn(f"{file_name} 100%", "📈")
                        else:
                            print(f"{file_name} 100%")
                else:
                    if log_fn:
                        log_fn(f"Executing: {cmd}", "➡️")
                    else:
                        print(f"{'#'*10} Executing the command: {cmd} {'#'*10}")
                    interact.send(cmd)
                    if idx == 0:
                        interact.expect(expert)
                    elif idx == 1:
                        interact.expect([expert, 'Password: '])
                        if interact.last_match == 'Password: ':
                            interact.send(password)
                            interact.expect(expert_root)
                    else:
                        interact.expect(expert_root)
                    # Emit CLI output lines
                    try:
                        out = (interact.current_output_clean or "").strip()
                        if out:
                            for line in out.splitlines():
                                if line.strip():
                                    if log_fn:
                                        log_fn(line, "📄")
                                    else:
                                        print(line)
                    except Exception:
                        pass
            if log_fn:
                log_fn("All commands executed", "📦")
            else:
                print(f"{'#'*10} All commands executed {'#'*10}")

    if log_fn:
        log_fn(f"SSH connection closed to FMC {host}", "🔒")
    else:
        print(f"SSH connection closed to FMC {host}")
    return {"success": True}

MODEL_TO_URL = {
    "1000": "upgrade/Cisco_FTD_SSP_FP1K_Upgrade-{ver}.sh.{ext}.tar",
    "1200": "aarch64/upgrade/Cisco_Secure_FW_TD_1200-{ver}.sh.{ext}.tar",
    "3100": "upgrade/Cisco_FTD_SSP_FP3K_Upgrade-{ver}.sh.{ext}.tar",
    "4100": "upgrade/Cisco_FTD_SSP_Upgrade-{ver}.sh.{ext}.tar",
    "4200": "upgrade/Cisco_Secure_FW_TD_4200-{ver}.sh.{ext}.tar",
    "FMC": "upgrade/Cisco_Secure_FW_Mgmt_Center_Upgrade-{ver}.sh.{ext}.tar",
}

def run_download_upgrade_on_device(
    ip: str,
    ssh_port: int,
    username_on_device: str,
    device_password: str,
    branch: str,
    version: str,
    models: List[str],
    timeout: int = 1200,
    log_fn: Optional[Callable[..., None]] = None,
) -> Dict[str, Any]:
    try:
        base_path = rel_path if (branch or "").lower().startswith("rel") else dev_path
        tar_ext = "REL" if (branch or "").lower().startswith("rel") else "DEV"
        full_version = version.strip()

        cmds = ['expert', 'sudo su', 'cd /var/sf/updates']
        for m in models:
            key = str(m).upper()
            if key not in ("1000","1200","3100","4100","4200","FMC"):
                continue
            # keep mapping keys canonical
            k = "FMC" if key == "FMC" else key
            path_fmt = MODEL_TO_URL[k if k == "FMC" else k]
            rel = path_fmt.format(ver=full_version, ext=tar_ext)
            cmds.append(f"wget {base_path}/{full_version}/{rel}")

        if log_fn:
            log_fn(f"Connecting to {ip}:{ssh_port} as {username_on_device}", "🔌")
        res = run_commands_over_ssh(ip, ssh_port, device_password, cmds, username_override=username_on_device, log_fn=log_fn)
        return res
    except Exception as e:
        if log_fn:
            log_fn(f"Error: {e}", "❌")
        return {"success": False, "error": str(e)}