from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback
import argparse
from typing import Optional, List, Callable, Dict, Any

HOST = "10.106.239.165"
USERNAME = "admin"
PASSWORD = "Cisco@12"
CLISH_PROMPT = "> "

FTD_PORTS = {
    # "wm-1": 12012,
    # "wm-2": 12013,
    # "wm-3": 12014,
    # "wm-4": 12015,
    # "wm-5": 12016,
    # "wm-6": 12017,
    # "wm-7": 12027,
    "WM-8": 12056,
    "WM-9": 12057,
    # # # # "KP-4": 12021,
    # # # # "KP-5": 12004,
    # "qw-1": 12031,
    # "qw-2": 12032,
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
    "VIC-1": 12003,
    "VIC-2": 12065,
    # "vFTD-116": 12116
    # "ARS-1": 12148,
    # "ARS-2": 12149 
}

COMMANDS = [
    'configure network static-routes ipv4 add management0 10.0.0.0 255.0.0.0 192.168.2.1',
    'configure network static-routes ipv4 add management0 173.0.0.0 255.0.0.0 192.168.2.1'
]

# Thread-safe printing
_print_lock = threading.Lock()

def _log(host: str, message: str, icon: str = ""):
    with _print_lock:
        prefix = f"[{host}]"
        if icon:
            print(f"{prefix} {icon} {message}")
        else:
            print(f"{prefix} {message}")


def run_static_routes_on_device(
    ip: str,
    ssh_port: int,
    username: str,
    device_password: str,
    commands: Optional[List[str]] = None,
    timeout: int = 30,
    log_fn: Optional[Callable[..., None]] = None,
) -> Dict[str, Any]:
    # If commands is None, use default. If an empty list is provided, execute nothing.
    cmds = COMMANDS if commands is None else commands
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
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
            timeout=timeout,
        )
        if log_fn:
            log_fn("SSH connection established", "✅")

        interact = SSHClientInteraction(client, timeout=timeout, display=False)
        if log_fn:
            log_fn("Waiting for CLI prompt", "⏳")
        interact.expect(CLISH_PROMPT)

        for cmd in cmds:
            if log_fn:
                log_fn(f"Executing: {cmd}", "➡️")
            interact.send(cmd)
            interact.expect(CLISH_PROMPT)
            # Emit CLI output after each command
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
    Normalize FTD_PORTS values to an iterable of integer ports.
    Supports:
    - int (single port)
    - str "start-end" (inclusive)
    - tuple/list (start, end) inclusive
    - range objects
    """
    if isinstance(value, int):
        if value <= 0:
            raise ValueError(
                "Detected non-positive port value. If you intended a range like 40001-40034, please quote it as a string: \"40001-40034\" or use a tuple (40001, 40034)."
            )
        return [value]
    if isinstance(value, str):
        s = value.strip()
        if "-" in s:
            start_s, end_s = s.split("-", 1)
            start, end = int(start_s.strip()), int(end_s.strip())
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
    for label, spec in FTD_PORTS.items():
        for p in _expand_port_spec(spec):
            tasks.append((f"{label}:{p}", p))
    return tasks

def _run_session(host_label: str, port: int):
    res = run_static_routes_on_device(
        ip=HOST,
        ssh_port=port,
        username=USERNAME,
        device_password=PASSWORD,
        commands=COMMANDS,
        timeout=30,
        log_fn=lambda msg, icon="": _log(host_label, msg, icon),
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
            print("No targets found in FTD_PORTS. Nothing to do.")
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
    parser = argparse.ArgumentParser(description="Configure static routes on FTD via SSH")
    parser.add_argument("--ip", help="Target device IP", default=HOST)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--ports", help="Ports spec, e.g. '22', '12056-12060', '22,2222'")
    parser.add_argument("--username", default=USERNAME)
    parser.add_argument("--password", default=PASSWORD)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    if args.ip and args.username and args.password:
        # Build targets similar to configure_http_proxy
        def _expand(s):
            return _expand_port_spec(s) if s else [args.ssh_port]
        targets = [(f"{args.ip}:{p}", int(p)) for p in _expand(args.ports)]
        with _print_lock:
            print(f"Launching parallel SSH sessions for {len(targets)} target(s)...")
        results = []
        with ThreadPoolExecutor(max_workers=min(16, len(targets) or 1)) as executor:
            futs = {executor.submit(run_static_routes_on_device, args.ip, p, args.username, args.password, COMMANDS, args.timeout, lambda m, i='': _log(f"{args.ip}:{p}", m, i)): p for _, p in targets}
            for f in as_completed(futs):
                res = f.result()
                results.append(res)
        succ = sum(1 for r in results if r.get("success"))
        with _print_lock:
            print("\n===== Summary =====")
            print(f"Successful: {succ}/{len(targets)}")
    else:
        run_all_parallel()

if __name__ == "__main__":
    main()