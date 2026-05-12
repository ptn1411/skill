#!/usr/bin/env python3
"""
dump_process.py — Dump process memory cross-platform.

Windows: comsvcs.dll MiniDump (built-in) or ProcDump (Sysinternals).
Linux:   /proc/<pid>/mem with /proc/<pid>/maps.

Usage:
    python dump_process.py --pid 1234 --out dumps/target.dmp
    python dump_process.py --name "TargetApp.exe" --out dumps/target.dmp
    python dump_process.py --pid 1234 --method procdump --out dumps/target.dmp
    python dump_process.py --list  # List candidate processes
"""

import argparse
import ctypes
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


def find_pid_by_name(name: str) -> list[dict]:
    """Find PIDs matching process name."""
    matches = []
    if sys.platform == 'win32':
        try:
            out = subprocess.check_output(
                ['tasklist', '/FO', 'CSV', '/NH'],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 2 and name.lower() in parts[0].lower():
                    matches.append({'name': parts[0], 'pid': int(parts[1])})
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(
                ['ps', '-eo', 'pid,comm'], text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines()[1:]:
                parts = line.split(None, 1)
                if len(parts) == 2 and name.lower() in parts[1].lower():
                    matches.append({'name': parts[1].strip(), 'pid': int(parts[0])})
        except Exception:
            pass
    return matches


def list_interesting_processes() -> list[dict]:
    """List non-system processes that are likely RE targets."""
    skip_names = {
        'svchost.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'smss.exe', 'conhost.exe', 'dwm.exe',
        'fontdrvhost.exe', 'sihost.exe', 'taskhostw.exe',
        'explorer.exe', 'RuntimeBroker.exe', 'System',
        'systemd', 'kthreadd', 'init',
    }
    procs = []
    if sys.platform == 'win32':
        try:
            out = subprocess.check_output(
                ['tasklist', '/FO', 'CSV', '/NH'],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 5 and parts[0] not in skip_names:
                    procs.append({
                        'name': parts[0],
                        'pid': int(parts[1]),
                        'mem_usage': parts[4] if len(parts) > 4 else 'N/A',
                    })
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(
                ['ps', '-eo', 'pid,rss,comm', '--sort=-rss'],
                text=True, stderr=subprocess.DEVNULL,
            )
            for line in out.strip().splitlines()[1:]:
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[2].strip() not in skip_names:
                    rss_kb = int(parts[1])
                    procs.append({
                        'name': parts[2].strip(),
                        'pid': int(parts[0]),
                        'mem_usage': f"{rss_kb // 1024} MB",
                    })
        except Exception:
            pass
    return procs[:50]


def dump_comsvcs(pid: int, out_path: Path) -> dict:
    """Dump using comsvcs.dll MiniDumpWriteDump (Windows built-in)."""
    print(f"[*] Dumping PID {pid} via comsvcs.dll...")

    cmd = (
        f'powershell -Command "'
        f"$p = Get-Process -Id {pid}; "
        f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
        f"MiniDump {pid} {out_path.resolve()} full"
        f'"'
    )

    try:
        result = subprocess.run(
            ['powershell', '-Command',
             f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, '
             f'MiniDump {pid} "{out_path.resolve()}" full'],
            capture_output=True, text=True, timeout=120,
        )

        if out_path.exists() and out_path.stat().st_size > 0:
            size_mb = out_path.stat().st_size / (1024 * 1024)
            print(f"[+] Dump saved: {out_path} ({size_mb:.1f} MB)")
            return {'method': 'comsvcs', 'size': out_path.stat().st_size, 'path': str(out_path)}

        print("[!] comsvcs.dll dump failed or empty, trying MiniDumpWriteDump API...")
        return dump_minidump_api(pid, out_path)

    except subprocess.TimeoutExpired:
        return {'error': 'Timeout during comsvcs dump'}
    except Exception as e:
        return {'error': str(e)}


def dump_minidump_api(pid: int, out_path: Path) -> dict:
    """Dump using ctypes MiniDumpWriteDump directly."""
    print(f"[*] Dumping PID {pid} via MiniDumpWriteDump API...")

    try:
        PROCESS_ALL_ACCESS = 0x1F0FFF
        kernel32 = ctypes.windll.kernel32
        dbghelp = ctypes.windll.dbghelp

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            return {'error': f'OpenProcess failed (error {kernel32.GetLastError()}). Run as Administrator.'}

        try:
            h_file = kernel32.CreateFileW(
                str(out_path.resolve()), 0x40000000, 0, None, 2, 0x80, None,
            )
            if h_file == -1:
                return {'error': f'CreateFile failed (error {kernel32.GetLastError()})'}

            try:
                MiniDumpWithFullMemory = 0x00000002
                success = dbghelp.MiniDumpWriteDump(
                    h_process, pid, h_file, MiniDumpWithFullMemory,
                    None, None, None,
                )

                if success:
                    size_mb = out_path.stat().st_size / (1024 * 1024)
                    print(f"[+] Dump saved: {out_path} ({size_mb:.1f} MB)")
                    return {'method': 'MiniDumpWriteDump', 'size': out_path.stat().st_size, 'path': str(out_path)}
                else:
                    return {'error': f'MiniDumpWriteDump failed (error {kernel32.GetLastError()})'}
            finally:
                kernel32.CloseHandle(h_file)
        finally:
            kernel32.CloseHandle(h_process)

    except Exception as e:
        return {'error': str(e)}


def dump_procdump(pid: int, out_path: Path) -> dict:
    """Dump using Sysinternals ProcDump."""
    procdump = shutil.which('procdump') or shutil.which('procdump64')
    if not procdump:
        return {'error': 'procdump not found. Download from Sysinternals.'}

    print(f"[*] Dumping PID {pid} via ProcDump...")
    try:
        result = subprocess.run(
            [procdump, '-ma', str(pid), str(out_path.resolve()), '-accepteula'],
            capture_output=True, text=True, timeout=120,
        )
        if out_path.exists() and out_path.stat().st_size > 0:
            size_mb = out_path.stat().st_size / (1024 * 1024)
            print(f"[+] Dump saved: {out_path} ({size_mb:.1f} MB)")
            return {'method': 'procdump', 'size': out_path.stat().st_size, 'path': str(out_path)}
        return {'error': f'ProcDump failed: {result.stderr[:500]}'}
    except subprocess.TimeoutExpired:
        return {'error': 'ProcDump timeout'}
    except Exception as e:
        return {'error': str(e)}


def dump_proc_mem(pid: int, out_path: Path) -> dict:
    """Dump using /proc/<pid>/mem + maps (Linux)."""
    maps_path = Path(f'/proc/{pid}/maps')
    mem_path = Path(f'/proc/{pid}/mem')

    if not maps_path.exists():
        return {'error': f'/proc/{pid}/maps not found. Is PID correct?'}

    print(f"[*] Dumping PID {pid} via /proc/mem...")

    try:
        maps_text = maps_path.read_text()
        regions = []
        for line in maps_text.splitlines():
            m = re.match(r'([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]+)', line)
            if m and 'r' in m.group(3):
                start = int(m.group(1), 16)
                end = int(m.group(2), 16)
                regions.append((start, end))

        total = 0
        with open(mem_path, 'rb') as mem_fd, open(out_path, 'wb') as out_fd:
            for start, end in regions:
                try:
                    mem_fd.seek(start)
                    chunk = mem_fd.read(end - start)
                    out_fd.write(chunk)
                    total += len(chunk)
                except (OSError, ValueError):
                    continue

        size_mb = total / (1024 * 1024)
        print(f"[+] Dump saved: {out_path} ({size_mb:.1f} MB, {len(regions)} regions)")
        return {
            'method': '/proc/mem',
            'size': total,
            'regions': len(regions),
            'path': str(out_path),
        }

    except PermissionError:
        return {'error': 'Permission denied. Run as root or use sudo.'}
    except Exception as e:
        return {'error': str(e)}


def dump_process(pid: int, out_path: Path, method: str = 'auto') -> dict:
    """Dump process memory using best available method."""
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == 'win32':
        if method == 'procdump':
            return dump_procdump(pid, out_path)
        elif method == 'api':
            return dump_minidump_api(pid, out_path)
        else:
            result = dump_comsvcs(pid, out_path)
            if 'error' in result and method == 'auto':
                print("[*] Falling back to ProcDump...")
                return dump_procdump(pid, out_path)
            return result
    else:
        return dump_proc_mem(pid, out_path)


def main() -> int:
    ap = argparse.ArgumentParser(description="Dump process memory (cross-platform)")
    ap.add_argument('--pid', type=int, help='Target process PID')
    ap.add_argument('--name', help='Find PID by process name')
    ap.add_argument('--method', choices=['auto', 'comsvcs', 'procdump', 'api', 'proc'],
                    default='auto', help='Dump method (default: auto)')
    ap.add_argument('--out', default='process.dmp', help='Output dump file')
    ap.add_argument('--list', action='store_true', help='List candidate processes')
    args = ap.parse_args()

    if args.list:
        procs = list_interesting_processes()
        if not procs:
            print("[!] No processes found")
            return 1
        print(f"[*] {len(procs)} candidate processes:")
        print(f"    {'PID':>8}  {'Memory':>10}  Name")
        print(f"    {'---':>8}  {'------':>10}  ----")
        for p in procs:
            print(f"    {p['pid']:>8}  {p.get('mem_usage', 'N/A'):>10}  {p['name']}")
        return 0

    pid = args.pid
    if not pid and args.name:
        matches = find_pid_by_name(args.name)
        if not matches:
            print(f"[!] No process matching '{args.name}'", file=sys.stderr)
            return 1
        if len(matches) > 1:
            print(f"[*] Multiple matches for '{args.name}':")
            for m in matches:
                print(f"    PID {m['pid']}: {m['name']}")
            print(f"[*] Using first match: PID {matches[0]['pid']}")
        pid = matches[0]['pid']

    if not pid:
        print("[!] Specify --pid or --name", file=sys.stderr)
        return 1

    print(f"[*] Target PID: {pid}")
    result = dump_process(pid, Path(args.out), args.method)

    if 'error' in result:
        print(f"[!] {result['error']}", file=sys.stderr)
        return 1

    print(f"\n[+] Dump complete:")
    print(f"    Method : {result['method']}")
    print(f"    Size   : {result['size'] / (1024*1024):.1f} MB")
    print(f"    Output : {result['path']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
