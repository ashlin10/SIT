import os
from dotenv import load_dotenv
load_dotenv()

from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

# Load from environment variables (no hardcoded credentials)
host1 = os.environ.get("DEFAULT_HOST", "")
username = os.environ.get("DEFAULT_SSH_USERNAME", "")
ftd_password = os.environ.get("DEFAULT_FTD_PASSWORD", "")
fmc_password = os.environ.get("DEFAULT_FMC_PASSWORD", "")
clish = "> "
expert = ".+\$\s+"
expert_root = ".+\#\s+"

ftd_port = {
    "WM-1": 12012,
    # "WM-2": 12013,
    "WM-3": 12014,
    # "WM-4": 12015,
    "WM-5": 12016,
    "WM-6": 12017,
    "WM-7": 12027,
    # "WM-8": 12056,
    # "WM-9": 12057,
    # # "KP-4": 12021,
    # # "KP-5": 12004,
    # "QP-1": 12031,
    # "QP-2": 12032,
    # "QP-3": 12033,
    # "QP-4": 12051,
    "TPK-1": 12054,
    "TPK-2": 12055,
    # "TPK-3": 12018,
    # "TPK-4": 12019,
    # "TPK-5": 12020,
    # # "TPK-6": 12030,
    "VIC-1": 12003,
    "VIC-2": 12065
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
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    commands = ['expert', 'sudo su']
    ipt_cmds = [
        'sudo iptables -t nat -A POSTROUTING -o management0+ -j MASQUERADE',
        'sudo iptables -t nat -A POSTROUTING -o tap_nlp -j MASQUERADE',
    ]
    try:
        _log(host_label, f"Connecting to {host1}:{port} as {username}", "🔌")
        client.connect(
            hostname=host1,
            username=username,
            password=ftd_password,
            port=port,
            look_for_keys=False,
            allow_agent=False,
            timeout=30,
        )
        _log(host_label, "SSH connection established", "✅")

        interact = SSHClientInteraction(client, timeout=60, display=False)
        _log(host_label, "Waiting for CLI prompt", "⏳")
        interact.expect(clish)

        # expert
        _log(host_label, f"Executing: {commands[0]}", "➡️")
        interact.send(commands[0])
        interact.expect(expert)
        # sudo su
        _log(host_label, f"Executing: {commands[1]}", "➡️")
        interact.send(commands[1])
        interact.expect([expert, 'Password: '])
        if interact.last_match == 'Password: ':
            interact.send(ftd_password)
            interact.expect(expert_root)

        # iptables commands
        for cmd in ipt_cmds:
            _log(host_label, f"Executing: {cmd}", "➡️")
            interact.send(cmd)
            interact.expect(expert_root)

        output = interact.current_output_clean
        _log(host_label, "Command execution completed", "📦")
        with _print_lock:
            print(f"[{host_label}] {'#'*10} Result {'#'*10}")
            print(output)
        return {"host": host_label, "success": True}
    except Exception as e:
        _log(host_label, f"Error: {e}", "❌")
        with _print_lock:
            traceback.print_exc()
        return {"host": host_label, "success": False, "error": str(e)}
    finally:
        try:
            client.close()
            _log(host_label, "SSH connection closed", "🔒")
        except Exception:
            pass

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
    run_all_parallel()

if __name__ == "__main__":
    main()