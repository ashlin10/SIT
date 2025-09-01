from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction
from time import sleep
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback
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
proxy_address = ".+address:\s*"
proxy_port = ".+Port:\s*"
proxy_auth = ".+\[n\]:\s*"

ftd_port = {
    # "WM-1": 12012,
    # "WM-2": 12013,
    # "WM-3": 12014,
    # "WM-4": 12015,
    # "WM-5": 12016,
    # "WM-6": 12017,
    # "WM-7": 12027,
    "WM-8": 12056,
    "WM-9": 12057,
    # # "KP-1": 12018,
    # # "KP-2": 12019,
    # # # "KP-3": 12020,
    # # "KP-4": 12021,
    # # "KP-5": 12004,
    # # # "KP-6": 12030,
    # "QP-1": 12031,
    # "QP-2": 12032,
    # "QP-3": 12033,
    # "QP-4": 12051,
    # "TPK-1": 12054,
    # "TPK-2": 12055,
    "VIC-1": 12003,
    "VIC-2": 12065,
    # "ARS-1": 12148,
    # "ARS-2": 12149,
    # "TPK-1-MI": "13111-13120",
    # "TPK-2-MI": "13211-13220",
    # "WA-1-MI": "40001-40034",
    # "WA-2-MI": "40035-40068", 
}

# Thread-safe printing
_print_lock = threading.Lock()

def _log(host: str, message: str, icon: str = ""):
    with _print_lock:
        prefix = f"[{host}]"
        if icon:
            print(f"{prefix} {icon} {message}")
        else:
            print(f"{prefix} {message}")


def configure_http_proxy_on_device(
    ip: str,
    ssh_port: int,
    username: str,
    device_password: str,
    proxy_address: str,
    proxy_port: int,
    proxy_auth: bool = False,
    proxy_username: str = None,
    proxy_password: str = None,
    timeout: int = 30,
    log_fn: Optional[Callable[..., None]] = None,
) -> Dict[str, Any]:
    """
    Connect to an FTD via SSH and configure HTTP proxy using clish prompts.
    Returns: {success: bool, output?: str, error?: str}
    """
    clish = "> "
    proxy_address_prompt = ".+address:\s*"
    proxy_port_prompt = ".+Port:\s*"
    proxy_auth_prompt = ".+\[n\]:\s*"
    proxy_user_prompt = ".*Enter\s+Proxy\s+Username:\s*"
    proxy_pass_prompt = ".*Enter\s+Proxy\s+Password:\s*"
    proxy_confirm_prompt = ".*Confirm\s+Proxy\s+Password:\s*"

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
        interact.expect(clish)
        # Emit initial prompt-output if any
        try:
            out = (interact.current_output_clean or "").strip()
            if out and log_fn:
                for line in out.splitlines():
                    if line.strip():
                        log_fn(line, "📄")
        except Exception:
            pass

        if log_fn:
            log_fn("Executing: configure network http-proxy", "➡️")
        interact.send('configure network http-proxy')
        interact.expect(proxy_address_prompt)
        try:
            out = (interact.current_output_clean or "").strip()
            if out and log_fn:
                for line in out.splitlines():
                    if line.strip():
                        log_fn(line, "📄")
        except Exception:
            pass
        if log_fn:
            log_fn(f"Sending proxy address: {proxy_address}", "📨")
        interact.send(str(proxy_address))
        interact.expect(proxy_port_prompt)
        try:
            out = (interact.current_output_clean or "").strip()
            if out and log_fn:
                for line in out.splitlines():
                    if line.strip():
                        log_fn(line, "📄")
        except Exception:
            pass
        if log_fn:
            log_fn(f"Sending proxy port: {proxy_port}", "📨")
        interact.send(str(proxy_port))
        interact.expect(proxy_auth_prompt)
        try:
            out = (interact.current_output_clean or "").strip()
            if out and log_fn:
                for line in out.splitlines():
                    if line.strip():
                        log_fn(line, "📄")
        except Exception:
            pass

        if proxy_auth:
            if log_fn:
                log_fn("Auth required? -> y", "📨")
            interact.send('y')
            interact.expect(proxy_user_prompt)
            try:
                out = (interact.current_output_clean or "").strip()
                if out and log_fn:
                    for line in out.splitlines():
                        if line.strip():
                            log_fn(line, "📄")
            except Exception:
                pass
            if log_fn:
                log_fn("Sending proxy username", "👤")
            interact.send(str(proxy_username or ''))
            interact.expect(proxy_pass_prompt)
            try:
                out = (interact.current_output_clean or "").strip()
                if out and log_fn:
                    for line in out.splitlines():
                        if line.strip():
                            log_fn(line, "📄")
            except Exception:
                pass
            if log_fn:
                log_fn("Sending proxy password", "🔑")
            interact.send(str(proxy_password or ''))
            interact.expect(proxy_confirm_prompt)
            try:
                out = (interact.current_output_clean or "").strip()
                if out and log_fn:
                    for line in out.splitlines():
                        if line.strip():
                            log_fn(line, "📄")
            except Exception:
                pass
            if log_fn:
                log_fn("Confirming proxy password", "🔒")
            interact.send(str(proxy_password or ''))
            interact.expect(clish)
            try:
                out = (interact.current_output_clean or "").strip()
                if out and log_fn:
                    for line in out.splitlines():
                        if line.strip():
                            log_fn(line, "📄")
            except Exception:
                pass
        else:
            if log_fn:
                log_fn("Auth required? -> n", "📨")
            interact.send('n')
            interact.expect(clish)
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
        except Exception:
            pass


def _run_session(host_label: str,
                 ip: str,
                 port: int,
                 username: str,
                 device_password: str,
                 proxy_address: str,
                 proxy_port: int,
                 proxy_auth: bool,
                 proxy_username: str,
                 proxy_password: str,
                 timeout: int = 30):
    _log(host_label, f"Connecting to {ip}:{port} as {username}", "🔌")
    res = configure_http_proxy_on_device(
        ip=ip,
        ssh_port=port,
        username=username,
        device_password=device_password,
        proxy_address=proxy_address,
        proxy_port=proxy_port,
        proxy_auth=proxy_auth,
        proxy_username=proxy_username,
        proxy_password=proxy_password,
        timeout=timeout,
        log_fn=lambda msg, icon="": _log(host_label, msg, icon),
    )
    if res.get("success"):
        _log(host_label, "Command execution completed", "📦")
    else:
        _log(host_label, f"Error: {res.get('error')}", "❌")
    return {"host": host_label, **res}


def _expand_port_spec(value):
    """
    Normalize ftd_port values to an iterable of integer ports.
    Supports:
    - int (single port)
    - str "start-end" (inclusive)
    - tuple/list (start, end) inclusive
    - range objects
    """
    # Single int
    if isinstance(value, int):
        if value <= 0:
            raise ValueError(
                "Detected non-positive port value. If you intended a range like 40001-40034, please quote it as a string: \"40001-40034\" or use a tuple (40001, 40034)."
            )
        return [value]

    # String "start-end"
    if isinstance(value, str):
        s = value.strip()
        if "-" in s:
            parts = s.split("-", 1)
            start, end = int(parts[0].strip()), int(parts[1].strip())
            if start > end:
                start, end = end, start
            return list(range(start, end + 1))
        # Single numeric string
        if s.isdigit():
            return [int(s)]
        raise ValueError(f"Unrecognized port spec string: {value}")

    # Tuple/List (start, end)
    if isinstance(value, (tuple, list)) and len(value) == 2:
        start, end = int(value[0]), int(value[1])
        if start > end:
            start, end = end, start
        return list(range(start, end + 1))

    # range object
    if isinstance(value, range):
        return list(value)

    raise ValueError(f"Unsupported port spec type: {type(value)} -> {value}")


def _build_targets_from_cli(ip: str, username: str, password: str, ports_spec: str):
    targets = []
    ports = _expand_port_spec(ports_spec) if ports_spec else [22]
    for p in ports:
        targets.append({
            "label": f"{ip}:{p}",
            "ip": ip,
            "port": int(p),
            "username": username,
            "password": password,
        })
    return targets


def run_targets_parallel(targets, proxy_address: str, proxy_port: int, proxy_auth: bool, proxy_username: str, proxy_password: str, max_workers: int = None, timeout: int = 30):
    total = len(targets)
    with _print_lock:
        print(f"Launching parallel SSH sessions for {total} target(s)...")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers or min(16, total or 1)) as executor:
        future_map = {
            executor.submit(
                _run_session,
                t["label"], t["ip"], t["port"], t["username"], t["password"],
                proxy_address, proxy_port, proxy_auth, proxy_username, proxy_password, timeout
            ): t for t in targets
        }
        for future in as_completed(future_map):
            res = future.result()
            results.append(res)

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure HTTP proxy on FTD via SSH")
    parser.add_argument("--ip", help="Target device IP")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (used if --ports not provided)")
    parser.add_argument("--ports", help="Ports spec (e.g., '22', '12056-12060', '22,2222')")
    parser.add_argument("--username", help="SSH username")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--proxy-address", required=False, help="Proxy address")
    parser.add_argument("--proxy-port", type=int, required=False, help="Proxy port")
    parser.add_argument("--proxy-auth", action="store_true", help="Use proxy authentication")
    parser.add_argument("--proxy-username", help="Proxy auth username")
    parser.add_argument("--proxy-password", help="Proxy auth password")
    parser.add_argument("--max-workers", type=int, default=16, help="Max parallel workers")
    parser.add_argument("--timeout", type=int, default=30, help="SSH and expect timeout")

    args = parser.parse_args()

    if args.ip and args.username and args.password and args.proxy_address and args.proxy_port is not None:
        targets = _build_targets_from_cli(args.ip, args.username, args.password, args.ports or str(args.ssh_port))
        run_targets_parallel(
            targets,
            proxy_address=args.proxy_address,
            proxy_port=args.proxy_port,
            proxy_auth=args.proxy_auth,
            proxy_username=args.proxy_username or "",
            proxy_password=args.proxy_password or "",
            max_workers=args.max_workers,
            timeout=args.timeout,
        )
    else:
        print("Insufficient arguments supplied; falling back to built-in demo map if any.")
        try:
            from sys import exit
            # No default targets provided; instruct user
            print("Usage example:\n  python configure_http_proxy.py --ip 10.0.0.1 --username admin --password pass --ports 12056-12060 --proxy-address 1.1.1.1 --proxy-port 80")
            exit(2)
        except Exception:
            pass