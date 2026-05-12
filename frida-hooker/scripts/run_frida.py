#!/usr/bin/env python3
"""
run_frida.py — Attach/spawn with Frida and inject hook scripts.

Captures hook output (console.log messages) to file for analysis.
Supports multiple scripts, timeout, and auto-detach.

Usage:
    python run_frida.py --attach "TargetApp.exe" --script hooks/bypass.js --out results/
    python run_frida.py --spawn "C:\\path\\target.exe" --script hooks/bypass.js --out results/
    python run_frida.py --attach 1234 --script hooks/a.js hooks/b.js --timeout 60
    python run_frida.py --list  # List running processes
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def check_frida() -> str | None:
    """Find frida CLI executable."""
    path = shutil.which('frida')
    if path:
        return path
    for candidate in [
        Path(sys.prefix) / 'Scripts' / 'frida.exe',
        Path.home() / '.local' / 'bin' / 'frida',
    ]:
        if candidate.exists():
            return str(candidate)
    return None


def list_processes() -> int:
    """List running processes via frida-ps."""
    frida_ps = shutil.which('frida-ps')
    if not frida_ps:
        print("[!] frida-ps not found. Install: pip install frida-tools", file=sys.stderr)
        return 1

    try:
        result = subprocess.run(
            [frida_ps], capture_output=True, text=True, timeout=10,
        )
        print(result.stdout)
        return 0
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1


def merge_scripts(script_paths: list[Path]) -> str:
    """Merge multiple JS scripts into one."""
    parts = []
    for path in script_paths:
        if not path.exists():
            print(f"[!] Script not found: {path}", file=sys.stderr)
            continue
        content = path.read_text(encoding='utf-8')
        parts.append(f"// === {path.name} ===")
        parts.append(content)
        parts.append("")
    return '\n'.join(parts)


def run_attach(target: str, scripts: list[Path], timeout: int,
               out_dir: Path | None) -> dict:
    """Attach to running process and inject scripts."""
    frida = check_frida()
    if not frida:
        return {'error': 'frida not found. Install: pip install frida-tools'}

    merged = merge_scripts(scripts)
    if not merged.strip():
        return {'error': 'No valid scripts to inject'}

    tmp_script = Path('_frida_merged.js')
    tmp_script.write_text(merged, encoding='utf-8')

    try:
        is_pid = target.isdigit()
        cmd = [frida]
        if is_pid:
            cmd.extend(['-p', target])
        else:
            cmd.extend(['-n', target])
        cmd.extend(['-l', str(tmp_script), '--no-pause'])

        print(f"[*] Attaching to {'PID ' + target if is_pid else target}...")
        print(f"[*] Scripts: {', '.join(p.name for p in scripts)}")
        if timeout > 0:
            print(f"[*] Timeout: {timeout}s")

        start_time = time.time()
        output_lines = []

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        try:
            while True:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    print(f"\n[*] Timeout reached ({timeout}s)")
                    break

                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break
                if line:
                    line = line.rstrip()
                    output_lines.append(line)
                    print(f"  {line}")

        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        elapsed = time.time() - start_time

        result = {
            'target': target,
            'mode': 'attach',
            'scripts': [str(p) for p in scripts],
            'duration': round(elapsed, 1),
            'output_lines': len(output_lines),
            'output': output_lines,
        }

        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            (out_dir / f'frida_output_{ts}.json').write_text(
                json.dumps(result, indent=2, ensure_ascii=False),
                encoding='utf-8',
            )
            (out_dir / f'frida_output_{ts}.log').write_text(
                '\n'.join(output_lines), encoding='utf-8',
            )

        return result

    finally:
        tmp_script.unlink(missing_ok=True)


def run_spawn(exe_path: str, scripts: list[Path], timeout: int,
              out_dir: Path | None) -> dict:
    """Spawn process with Frida and inject scripts."""
    frida = check_frida()
    if not frida:
        return {'error': 'frida not found. Install: pip install frida-tools'}

    merged = merge_scripts(scripts)
    if not merged.strip():
        return {'error': 'No valid scripts to inject'}

    if not Path(exe_path).exists():
        return {'error': f'Executable not found: {exe_path}'}

    tmp_script = Path('_frida_merged.js')
    tmp_script.write_text(merged, encoding='utf-8')

    try:
        cmd = [frida, '-f', exe_path, '-l', str(tmp_script), '--no-pause']

        print(f"[*] Spawning: {exe_path}")
        print(f"[*] Scripts: {', '.join(p.name for p in scripts)}")

        start_time = time.time()
        output_lines = []

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        try:
            while True:
                if timeout > 0 and (time.time() - start_time) > timeout:
                    print(f"\n[*] Timeout reached ({timeout}s)")
                    break

                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break
                if line:
                    line = line.rstrip()
                    output_lines.append(line)
                    print(f"  {line}")

        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        elapsed = time.time() - start_time

        result = {
            'target': exe_path,
            'mode': 'spawn',
            'scripts': [str(p) for p in scripts],
            'duration': round(elapsed, 1),
            'output_lines': len(output_lines),
            'output': output_lines,
        }

        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            (out_dir / f'frida_output_{ts}.json').write_text(
                json.dumps(result, indent=2, ensure_ascii=False),
                encoding='utf-8',
            )
            (out_dir / f'frida_output_{ts}.log').write_text(
                '\n'.join(output_lines), encoding='utf-8',
            )

        return result

    finally:
        tmp_script.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run Frida hooks on target process")
    ap.add_argument('--attach', help='Attach to process (name or PID)')
    ap.add_argument('--spawn', help='Spawn executable with hooks')
    ap.add_argument('--script', nargs='+', help='Frida JS script(s) to inject')
    ap.add_argument('--timeout', type=int, default=0,
                    help='Auto-stop after N seconds (0=manual, default: 0)')
    ap.add_argument('--out', help='Output directory for captured data')
    ap.add_argument('--list', action='store_true', help='List running processes')
    args = ap.parse_args()

    if args.list:
        return list_processes()

    if not args.attach and not args.spawn:
        print("[!] Specify --attach or --spawn", file=sys.stderr)
        return 1

    if not args.script:
        print("[!] Specify at least one --script", file=sys.stderr)
        return 1

    scripts = [Path(s) for s in args.script]
    out_dir = Path(args.out) if args.out else None

    if args.attach:
        result = run_attach(args.attach, scripts, args.timeout, out_dir)
    else:
        result = run_spawn(args.spawn, scripts, args.timeout, out_dir)

    if 'error' in result:
        print(f"[!] {result['error']}", file=sys.stderr)
        return 1

    print(f"\n[+] Frida session complete:")
    print(f"    Mode     : {result['mode']}")
    print(f"    Target   : {result['target']}")
    print(f"    Duration : {result['duration']}s")
    print(f"    Output   : {result['output_lines']} lines")
    if out_dir:
        print(f"    Saved to : {out_dir}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
