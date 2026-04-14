#!/usr/bin/env python3
import argparse
import asyncio
import gzip
import logging
import os
import re
import signal
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any

REPORT_FILE_DEFAULT = "/var/log/tunnel-disconnect-syslog.log"
DAEMON_LOG_DEFAULT = "/var/log/tunnel-monitor-daemon.log"
COUNT_FILE_DEFAULT = "/var/run/tunnel-monitor-daemon.count"

# ── Timestamp regexes (unified for all log types) ──
# ISO 8601: 2026-04-10T13:49:14Z or 2026-04-10T13:49:14+00:00
RE_TS_ISO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2}))\s'
)
# Bracket: [2026-04-10 13:49:14]  (swanctl --log format via `ts`)
RE_TS_BRACKET = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\]\s'
)
# Plain: 2026-04-10 13:49:14  (space-separated date time)
RE_TS_PLAIN = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s'
)
# Traditional syslog: Apr 10 13:49:14
RE_TS_SYSLOG = re.compile(
    r'^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s'
)
# 750007 disconnect event pattern (FTD syslog)
RE_750007 = re.compile(
    r'%FTD-\d+-750007:\s*Local:([^\s]+)\s+Remote:([^\s]+)\s+Username:([^\s]+)\s+.*?Reason:\s*(.*)',
    re.IGNORECASE
)


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse a timestamp string from any supported log format into a tz-aware datetime."""
    # ISO 8601
    try:
        ts_str_clean = ts_str.replace('Z', '+00:00')
        ts = datetime.fromisoformat(ts_str_clean)
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        pass
    # YYYY-MM-DD HH:MM:SS
    try:
        ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
        return ts.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        pass
    # Syslog: Apr 10 13:49:14  (no year — assume current year)
    try:
        ts = datetime.strptime(ts_str, '%b %d %H:%M:%S')
        return ts.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def extract_timestamp(line: str) -> Optional[datetime]:
    """Extract a timestamp from any supported log line format."""
    for regex in (RE_TS_ISO, RE_TS_BRACKET, RE_TS_PLAIN, RE_TS_SYSLOG):
        match = regex.match(line)
        if match:
            ts = parse_timestamp(match.group(1))
            if ts:
                return ts
    return None


def read_file_lines(filepath: str) -> List[str]:
    try:
        if filepath.endswith('.gz'):
            with gzip.open(filepath, 'rt', errors='replace') as handle:
                return [line.rstrip('\n') for line in handle if line.strip()]
        with open(filepath, 'r', errors='replace') as handle:
            return [line.rstrip('\n') for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def list_log_files(base_filename: str) -> List[str]:
    base = base_filename.replace('.gz', '')
    files = []
    try:
        for name in os.listdir('/var/log'):
            if name.startswith(base):
                files.append(os.path.join('/var/log', name))
    except FileNotFoundError:
        return []
    return sorted(files)


def collect_logs_in_window(filepaths: List[str], start_ts: datetime, end_ts: datetime) -> List[str]:
    """Collect log lines within a time window. Works with any supported timestamp format."""
    collected = []
    for filepath in filepaths:
        for line in read_file_lines(filepath):
            ts = extract_timestamp(line)
            if ts and start_ts <= ts <= end_ts:
                collected.append(line)
    return collected


def parse_750007_entries(lines: List[str]) -> List[Dict[str, Any]]:
    """Parse 750007 disconnect events from log lines (any format)."""
    entries = []
    for line in lines:
        ts = extract_timestamp(line)
        m_750007 = RE_750007.search(line)
        if ts and m_750007:
            local_endpoint = m_750007.group(1)
            remote_endpoint = m_750007.group(2)
            username = m_750007.group(3)
            reason = m_750007.group(4).strip()
            local_parts = local_endpoint.rsplit(':', 1)
            remote_parts = remote_endpoint.rsplit(':', 1)
            entries.append({
                'timestamp': ts,
                'local_ip': local_parts[0] if len(local_parts) > 1 else local_endpoint,
                'local_port': local_parts[1] if len(local_parts) > 1 else '',
                'remote_ip': remote_parts[0] if len(remote_parts) > 1 else remote_endpoint,
                'remote_port': remote_parts[1] if len(remote_parts) > 1 else '',
                'username': username,
                'reason': reason,
                'raw': line
            })
    return entries


def format_summary_table(entries: List[Dict[str, Any]]) -> str:
    if not entries:
        return "  No tunnel disconnect events detected.\n"
    header = f"  {'Timestamp':<19} {'Local IP:Port':<30} {'Remote IP:Port':<30} {'Username':<20} {'Reason':<30}"
    sep = f"  {'-'*19} {'-'*30} {'-'*30} {'-'*20} {'-'*30}"
    rows = [header, sep]
    for e in entries:
        ts = e['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if e.get('timestamp') else ''
        local_ep = f"{e['local_ip']}:{e['local_port']}"
        remote_ep = f"{e['remote_ip']}:{e['remote_port']}"
        rows.append(
            f"  {ts:<19} {local_ep:<30} {remote_ep:<30} {e['username']:<20} {e['reason']:<30}"
        )
    return '\n'.join(rows) + '\n'


def format_report_section(
    interval_start: datetime,
    interval_end: datetime,
    entries_750007: List[Dict[str, Any]],
    local_logs: List[str],
    remote_logs: List[str]
) -> str:
    section = []
    section.append("=" * 80)
    section.append(f"Interval: {interval_start.isoformat()} — {interval_end.isoformat()}")
    section.append("=" * 80)
    section.append("")

    section.append("Tunnel Down Summary")
    section.append("-" * 40)
    section.append(format_summary_table(entries_750007))
    section.append("")

    section.append("Local Logs")
    section.append("-" * 40)
    if local_logs:
        for line in local_logs:
            section.append(f"  {line}")
    else:
        section.append("  No local logs found in this interval.")
    section.append("")

    section.append("Remote Logs")
    section.append("-" * 40)
    if remote_logs:
        for line in remote_logs:
            section.append(f"  {line}")
    else:
        section.append("  No remote logs found in this interval.")
    section.append("")

    return '\n'.join(section) + '\n'


class LocalTunnelMonitor:
    def __init__(
        self,
        local_log: str,
        remote_log: str,
        interval_seconds: int,
        leeway_seconds: int,
        report_file: str,
        count_file: str
    ):
        self.local_log = local_log
        self.remote_log = remote_log
        self.interval_seconds = interval_seconds
        self.leeway_seconds = leeway_seconds
        self.report_file = report_file
        self.count_file = count_file
        self.last_processed_ts: Optional[datetime] = None
        self.disconnect_count = 0

    def _write_count(self) -> None:
        try:
            with open(self.count_file, 'w', errors='replace') as handle:
                handle.write(str(self.disconnect_count))
        except Exception:
            logging.exception("Failed to write disconnect count")

    def _process_interval(self, interval_start: datetime, interval_end: datetime) -> None:
        local_files = list_log_files(self.local_log)
        remote_files = list_log_files(self.remote_log)

        # Collect ALL lines from both log sources in this interval
        local_interval_lines = collect_logs_in_window(local_files, interval_start, interval_end)
        remote_interval_lines = collect_logs_in_window(remote_files, interval_start, interval_end)

        # Search BOTH local and remote logs for 750007 disconnect events
        all_interval_lines = local_interval_lines + remote_interval_lines
        entries_750007 = parse_750007_entries(all_interval_lines)
        self.disconnect_count += len(entries_750007)

        if not entries_750007:
            report_section = format_report_section(interval_start, interval_end, [], [], [])
            with open(self.report_file, 'a', errors='replace') as handle:
                handle.write(report_section)
            logging.info("No 750007 events in interval %s — %s", interval_start, interval_end)
            self._write_count()
            return

        timestamps = [e['timestamp'] for e in entries_750007 if e['timestamp']]
        if not timestamps:
            report_section = format_report_section(interval_start, interval_end, entries_750007, [], [])
            with open(self.report_file, 'a', errors='replace') as handle:
                handle.write(report_section)
            self._write_count()
            return

        # Build a leeway window around the 750007 events
        first_ts = min(timestamps)
        last_ts = max(timestamps)
        leeway = timedelta(seconds=self.leeway_seconds)
        window_start = first_ts - leeway
        window_end = last_ts + leeway

        # Collect logs from both sources within the leeway window
        local_lines = collect_logs_in_window(local_files, window_start, window_end)
        remote_lines = collect_logs_in_window(remote_files, window_start, window_end)

        report_section = format_report_section(
            interval_start,
            interval_end,
            entries_750007,
            local_lines,
            remote_lines
        )
        with open(self.report_file, 'a', errors='replace') as handle:
            handle.write(report_section)
        logging.info("Appended report section for interval %s — %s", interval_start, interval_end)
        self._write_count()

    async def run(self, stop_event: asyncio.Event) -> None:
        self.last_processed_ts = datetime.now(timezone.utc)

        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.interval_seconds)
                if stop_event.is_set():
                    break
            except asyncio.TimeoutError:
                pass

            interval_end = datetime.now(timezone.utc)
            interval_start = self.last_processed_ts

            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, self._process_interval, interval_start, interval_end
                )
            except Exception as exc:
                logging.exception("Monitoring interval error: %s", exc)

            self.last_processed_ts = interval_end


async def main() -> None:
    parser = argparse.ArgumentParser(description="Tunnel disconnect monitor daemon")
    parser.add_argument('--local-log', required=True)
    parser.add_argument('--remote-log', required=True)
    parser.add_argument('--interval', type=int, default=300, help='Monitoring interval in seconds')
    parser.add_argument('--leeway', type=int, default=5)
    parser.add_argument('--report-file', default=REPORT_FILE_DEFAULT)
    parser.add_argument('--daemon-log', default=DAEMON_LOG_DEFAULT)
    parser.add_argument('--count-file', default=COUNT_FILE_DEFAULT)
    args = parser.parse_args()

    logging.basicConfig(
        filename=args.daemon_log,
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    logging.info("Starting tunnel monitor daemon. local_log=%s remote_log=%s", args.local_log, args.remote_log)

    daemon_start_ts = datetime.now(timezone.utc)
    try:
        with open(args.report_file, 'a', errors='replace') as handle:
            handle.write("=" * 80 + "\n")
            handle.write(f"Daemon start time (UTC): {daemon_start_ts.isoformat()}\n")
            handle.write("=" * 80 + "\n\n")
    except Exception:
        logging.exception("Failed to write daemon start time to report")

    stop_event = asyncio.Event()

    def _handle_signal(signum, _frame):
        logging.info("Received signal %s, shutting down.", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    monitor = LocalTunnelMonitor(
        local_log=args.local_log,
        remote_log=args.remote_log,
        interval_seconds=args.interval,
        leeway_seconds=args.leeway,
        report_file=args.report_file,
        count_file=args.count_file
    )
    await monitor.run(stop_event)


if __name__ == '__main__':
    asyncio.run(main())
