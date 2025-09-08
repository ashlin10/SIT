from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback
import re
import argparse
from typing import Optional, Callable, Dict, Any

host1 = "10.106.239.165"
username = "admin"
# ftd_password = ")YA*%Y85D+`p48M&"
ftd_password = "Cisco@12"
fmc_password = "Cisco@123"

clish = "> "
expert = ".+\$\s+"
expert_root = ".+\#\s+"


ftd_port = {
    "WM-1": 12012,
    # "WM-2": 12013,
    "WM-3": 12014,
    "WM-4": 12015,
    "WM-5": 12016,
    "WM-6": 12017,
    "WM-7": 12027,
    # # # "WM-8": 12056,
    # # # "WM-9": 12057,
    # # # # # "KP-4": 12021,
    # # # # # "KP-5": 12004,
    "QP-1": 12031,
    "QP-2": 12032,
    "QP-3": 12033,
    "QP-4": 12051,
    "TPK-1": 12054,
    "TPK-2": 12055,
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

fmc_port = {
#    "FMCvA": 12108,
   # "FMCvB": 12103
}

pattern = r"\b(TPK|WA|VIC).*"

# Thread-safe printing
_print_lock = threading.Lock()

def _log(host: str, message: str, icon: str = ""):
    with _print_lock:
        prefix = f"[{host}]"
        if icon:
            print(f"{prefix} {icon} {message}")
        else:
            print(f"{prefix} {message}")


def run_copy_dev_cert_on_device(
    ip: str,
    ssh_port: int,
    username: str,
    device_password: str,
    label: str = None,
    device_type: str = "FTD",
    timeout: int = 60,
    log_fn: Optional[Callable[..., None]] = None,
) -> Dict[str, Any]:
    """Copy dev certificate sequence with emoji logs and sudo handling.
    Returns {success: bool, output?: str, error?: str}
    """
    base_label = (label or ip).split(":", 1)[0]
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    # Default command sets
    commands = ['expert', 'sudo su', 'cd /ngfw/etc/certs', 'rm -f dev.crt*', 'wget -O dev.crt http://10.105.206.23/dev.crt']
    commands_misc = ['expert', 'sudo su', 'cd /opt/cisco/platform/certs/',
                     'rm -f fmc_dev.crt', 'rm -f fmc_dev.crt.sign', 'wget http://10.105.206.23/TPKDEVKEY/fmc_dev.crt',
                     'wget http://10.105.206.23/TPKDEVKEY/fmc_dev.crt.sign', 'cd /ngfw/etc/certs/', 'rm -f dev.crt*',
                     'wget http://10.105.206.23/TPKDEVKEY/dev.crt']
    commands_fmc = ['expert', 'sudo su', 'cd /etc/certs', 'rm -f dev.crt*', 'wget -O dev.crt http://10.105.206.23/dev.crt']
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

        interact = SSHClientInteraction(client, timeout=timeout, display=False)
        if log_fn:
            log_fn("Waiting for CLI prompt", "⏳")
        interact.expect(clish)
        try:
            out = (interact.current_output_clean or "").strip()
            if out and log_fn:
                for line in out.splitlines():
                    if line.strip():
                        log_fn(line, "📄")
        except Exception:
            pass

        # Decide command sequence based on device type and name prefix
        dev_type = (device_type or "FTD").upper()
        if dev_type == "FMC":
            seq = commands_fmc
        else:
            # For FTDs whose name starts with tpk, wa or vic (case-insensitive), use misc commands
            if re.match(r'^(tpk|wa|vic)', base_label.strip(), re.IGNORECASE):
                seq = commands_misc
            else:
                seq = commands

        # expert
        if log_fn:
            log_fn(f"Executing: {seq[0]}", "➡️")
        interact.send(seq[0])
        interact.expect(expert)
        try:
            out = (interact.current_output_clean or "").strip()
            if out and log_fn:
                for line in out.splitlines():
                    if line.strip():
                        log_fn(line, "📄")
        except Exception:
            pass
        # sudo su
        if log_fn:
            log_fn(f"Executing: {seq[1]}", "➡️")
        interact.send(seq[1])
        interact.expect([expert, 'Password: '])
        if interact.last_match == 'Password: ':
            interact.send(device_password)
            interact.expect(expert_root)
        try:
            out = (interact.current_output_clean or "").strip()
            if out and log_fn:
                for line in out.splitlines():
                    if line.strip():
                        log_fn(line, "📄")
        except Exception:
            pass
        # remaining commands
        for cmd in seq[2:]:
            if log_fn:
                log_fn(f"Executing: {cmd}", "➡️")
            interact.send(cmd)
            interact.expect(expert_root)
            try:
                out = (interact.current_output_clean or "").strip()
                if out and log_fn:
                    for line in out.splitlines():
                        if line.strip():
                            log_fn(line, "📄")
            except Exception:
                pass

        output = interact.current_output_clean
        if log_fn:
            log_fn("Command execution completed", "📦")
        return {"success": True, "output": output}
    except Exception as e:
        if log_fn:
            log_fn(f"Error: {e}", "❌")
        return {"success": False, "error": str(e)}
    finally:
        try:
            client.close()
            if log_fn:
                log_fn("SSH connection closed", "🔒")
        except Exception:
            pass

def _expand_port_spec(value):
    """
    Normalize ftd_port values to an iterable of integer ports.
    Supports int, "start-end" string, (start,end) tuple/list, or range.
    """
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("Port must be positive")
        return [value]
    if isinstance(value, str):
        s = value.strip()
        if "-" in s:
            a, b = s.split("-", 1)
            start, end = int(a.strip()), int(b.strip())
            if start > end:
                start, end = end, start
            return list(range(start, end + 1))
        if s.isdigit():
            return [int(s)]
        raise ValueError(f"Unrecognized port spec string: {value}")
    if isinstance(value, (tuple, list)) and len(value) == 2:
        start, end = int(value[0]), int(value[1])
        if start > end:
            start, end = end, start
        return list(range(start, end + 1))
    if isinstance(value, range):
        return list(value)
    raise ValueError(f"Unsupported port spec type: {type(value)} -> {value}")

def _build_tasks():
    tasks = []  # list of (host_label_with_port, port)
    for label, spec in ftd_port.items():
        for p in _expand_port_spec(spec):
            tasks.append((f"{label}:{p}", p))
    return tasks

def _run_session(host_label: str, port: int):
    res = run_copy_dev_cert_on_device(
        ip=host1,
        ssh_port=port,
        username=username,
        device_password=ftd_password,
        label=host_label,
        timeout=60,
        log_fn=lambda m, i='': _log(host_label, m, i),
    )
    return {"host": host_label, **res}

def run_all_parallel(max_workers: int = None):
    tasks = _build_tasks()
    total = len(tasks)
    with _print_lock:
        print(f"Launching parallel SSH sessions for {total} target(s)...")
    results = []
    if total == 0:
        with _print_lock:
            print("No targets found in ftd_port. Nothing to do.")
        return
    with ThreadPoolExecutor(max_workers=max_workers or min(16, total)) as executor:
        future_map = {executor.submit(_run_session, host_label, port): host_label for (host_label, port) in tasks}
        for future in as_completed(future_map):
            results.append(future.result())
    success = sum(1 for r in results if r.get("success"))
    fail = total - success
    with _print_lock:
        print("\n===== Summary =====")
        print(f"Successful: {success}/{total}")
        if fail:
            print("Failures:")
            for r in results:
                if not r.get("success"):
                    print(f"  - {r['host']}: {r.get('error', 'Unknown error')}")

def main():
    parser = argparse.ArgumentParser(description="Copy dev certificate to FTD via SSH")
    parser.add_argument("--ip", help="Target device IP", default=host1)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ports", help="Ports spec, e.g. '22', '12056-12060', '22,2222'")
    parser.add_argument("--username", default=username)
    parser.add_argument("--password", default=ftd_password)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    def _expand(value):
        if not value:
            return [args.ssh_port]
        s = str(value)
        if '-' in s:
            a, b = [int(x.strip()) for x in s.split('-', 1)]
            if a > b: a, b = b, a
            return list(range(a, b+1))
        if ',' in s:
            return [int(x.strip()) for x in s.split(',') if x.strip()]
        return [int(s)]

    targets = [(f"{args.ip}:{p}", int(p)) for p in _expand(args.ports)]
    with _print_lock:
        print(f"Launching parallel SSH sessions for {len(targets)} target(s)...")
    results = []
    with ThreadPoolExecutor(max_workers=min(16, len(targets) or 1)) as executor:
        futs = {executor.submit(run_copy_dev_cert_on_device, args.ip, p, args.username, args.password, f"{args.ip}:{p}", args.timeout, lambda m, i='': _log(f"{args.ip}:{p}", m, i)): p for _, p in targets}
        for f in as_completed(futs):
            results.append(f.result())
    succ = sum(1 for r in results if r.get("success"))
    with _print_lock:
        print("\n===== Summary =====")
        print(f"Successful: {succ}/{len(targets)}")

if __name__ == "__main__":
    main()