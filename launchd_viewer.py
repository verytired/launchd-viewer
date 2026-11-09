#!/usr/bin/env python3
"""launchd configuration viewer - macOS launchd services visualizer"""

import hashlib
import json
import os
import plistlib
import re
import subprocess
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import signal
import sys

HOME = os.path.expanduser("~")
MONITORED = ("User Agents", "Global Agents", "Global Daemons")
BASELINE_PATH = Path(__file__).resolve().parent / "baseline.json"
MONITOR_INTERVAL = 10  # seconds
SUSPICIOUS_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/", "/dev/shm/")
INTERPRETERS = {"sh", "bash", "zsh", "dash", "env", "python", "python3", "perl", "ruby", "osascript", "node", "php"}
BAD_PATTERNS = {"curl": r"\bcurl\b", "wget": r"\bwget\b", "base64": r"base64", "| sh": r"\|\s*(ba|z)?sh\b",
                "eval": r"\beval\b", "nc": r"\bnc\b", "/dev/tcp": r"/dev/tcp/", "chmod +x": r"\bchmod\s+\+x",
                "xattr -d": r"\bxattr\s+-d"}
MACHO_MAGIC = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}

PLIST_DIRS = {
    "User Agents": os.path.expanduser("~/Library/LaunchAgents"),
    "Global Agents": "/Library/LaunchAgents",
    "Global Daemons": "/Library/LaunchDaemons",
    "System Agents": "/System/Library/LaunchAgents",
    "System Daemons": "/System/Library/LaunchDaemons",
}


def get_launchctl_list():
    """Get running services from launchctl list."""
    result = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
    services = {}
    for line in result.stdout.strip().split("\n")[1:]:
        parts = line.split("\t")
        if len(parts) == 3:
            pid, status, label = parts
            services[label] = {
                "pid": int(pid) if pid != "-" else None,
                "status": int(status) if status != "-" else None,
            }
    return services


def parse_plist(filepath):
    """Parse a plist file and return its contents."""
    try:
        with open(filepath, "rb") as f:
            return plistlib.load(f)
    except Exception:
        try:
            result = subprocess.run(
                ["plutil", "-convert", "json", "-o", "-", filepath],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception:
            pass
    return None


_cache = {}


def cached(fn, path):
    """Memoize fn(path) on (fn, path, mtime, size) so 5s refreshes stay cheap."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (fn.__name__, path, st.st_mtime, st.st_size)
    if key not in _cache:
        _cache[key] = fn(path)
    return _cache[key]


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_macho(path):
    with open(path, "rb") as f:
        return f.read(4) in MACHO_MAGIC


def signer(path):
    """'unsigned' / 'adhoc' / first Authority (e.g. 'Software Signing', 'Developer ID Application: ...')."""
    out = subprocess.run(["codesign", "-dv", "--verbose=2", path], capture_output=True, text=True).stderr
    if "not signed" in out:
        return "unsigned"
    for line in out.splitlines():
        if line.startswith("Authority="):
            return line.split("=", 1)[1]
    return "adhoc" if "Signature=adhoc" in out else "unknown"


def plist_args(plist):
    if not plist:
        return []
    args = [str(plist["Program"])] if plist.get("Program") else []
    return args + [str(a) for a in plist.get("ProgramArguments") or []]


def exec_target(args):
    """The file actually run: the script for `bash script.sh`, else the program itself."""
    if not args:
        return None
    if os.path.basename(args[0]) in INTERPRETERS:
        for a in args[1:]:
            if not a.startswith("-") and os.path.isfile(a):
                return a
    return args[0]


def snapshot():
    """{plist path: {plist hash, exec target, target hash}} for the monitored dirs."""
    snap = {}
    for cat in MONITORED:
        d = PLIST_DIRS[cat]
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if not fn.endswith(".plist"):
                continue
            p = os.path.join(d, fn)
            target = exec_target(plist_args(parse_plist(p)))
            snap[p] = {"plist": cached(file_hash, p), "target": target,
                       "targetHash": cached(file_hash, target) if target and os.path.isfile(target) else None}
    return snap


def load_baseline():
    try:
        return json.loads(BASELINE_PATH.read_text())
    except (OSError, ValueError):
        return None


def save_baseline(snap):
    BASELINE_PATH.write_text(json.dumps(snap, indent=1))


def assess(plist, filepath, label, args, snap_entry, base_entry):
    """Heuristic red flags: list of (severity 1-3, message)."""
    flags = []
    if plist is None:
        flags.append((2, "plist を解析できない"))
    program = args[0] if args else None
    if program and program.startswith("/") and not os.path.exists(program):
        flags.append((2, f"実行ファイルが存在しない: {program}"))
    target = exec_target(args)
    for a in args:
        run = a == target  # the executed file is what matters; other args (sockets, data) only hint
        if a.startswith(SUSPICIOUS_DIRS):
            flags.append((3 if run else 1, f"一時/共有ディレクトリ{'から実行' if run else 'のパスを引数に'}: {a}"))
        elif a.startswith("/") and re.search(r"/\.[^/.]", a):
            flags.append((2 if run else 1, f"隠しディレクトリ{'から実行' if run else 'のパスを引数に'}: {a}"))
    cmd = " ".join(args)
    hits = [name for name, pat in BAD_PATTERNS.items() if re.search(pat, cmd, re.I)]
    if hits:
        flags.append((3, "危険なコマンド断片: " + ", ".join(hits)))
    elif program and os.path.basename(program) in INTERPRETERS and any(a in ("-c", "-e") for a in args[1:]):
        flags.append((2, "インタプリタにインラインコードを渡している"))

    sig = None
    if program and os.path.isfile(program) and cached(is_macho, program):
        sig = cached(signer, program)
        if sig in ("unsigned", "adhoc"):
            flags.append((2, f"署名なしバイナリ ({sig})"))
    if label.startswith("com.apple.") and not ("Software Signing" in (sig or "") or (sig or "").startswith("Apple")):
        flags.append((3, "com.apple.* を名乗るが Apple 署名ではない"))

    stem = os.path.basename(filepath)[:-len(".plist")]
    if plist and plist.get("Label") and plist["Label"] != stem:
        flags.append((1, f"Label とファイル名が不一致 ({stem}.plist)"))
    st = os.stat(filepath)
    if not filepath.startswith(HOME) and st.st_uid != 0:
        flags.append((2, "/Library 配下なのに所有者が root でない"))
    if st.st_mode & 0o022:
        flags.append((2, "plist が group/other から書き込み可能"))
    if time.time() - st.st_mtime < 7 * 86400:
        flags.append((1, "7日以内に変更された"))

    if base_entry is None:
        flags.append((2, "ベースラインにない新規 plist"))
    else:
        if base_entry.get("plist") != snap_entry["plist"]:
            flags.append((2, "plist の内容がベースラインから変更"))
        if base_entry.get("target") != snap_entry["target"] or base_entry.get("targetHash") != snap_entry["targetHash"]:
            flags.append((3, f"実行ファイルがベースラインから変更: {snap_entry['target']}"))
    return flags, sig


def collect_data():
    """Collect all launchd data."""
    running = get_launchctl_list()
    services = []
    snap = snapshot()
    baseline = load_baseline()
    if baseline is None:  # first run: current state becomes the baseline
        save_baseline(snap)
        baseline = snap

    for category, dirpath in PLIST_DIRS.items():
        if not os.path.isdir(dirpath):
            continue
        for filename in sorted(os.listdir(dirpath)):
            if not filename.endswith(".plist"):
                continue
            filepath = os.path.join(dirpath, filename)
            plist = parse_plist(filepath)
            label = plist.get("Label", filename.replace(".plist", "")) if plist else filename.replace(".plist", "")

            runtime = running.get(label, {})
            pid = runtime.get("pid")
            status = runtime.get("status")

            program = None
            if plist:
                program = plist.get("Program")
                if not program:
                    args = plist.get("ProgramArguments")
                    if args and len(args) > 0:
                        program = args[0]

            run_at_load = plist.get("RunAtLoad", False) if plist else False
            keep_alive = plist.get("KeepAlive", False) if plist else False
            disabled = plist.get("Disabled", False) if plist else False

            if isinstance(keep_alive, dict):
                keep_alive_detail = keep_alive
                keep_alive = True
            else:
                keep_alive_detail = None

            start_interval = plist.get("StartInterval") if plist else None
            start_calendar = plist.get("StartCalendarInterval") if plist else None
            watch_paths = plist.get("WatchPaths") if plist else None

            if pid is not None:
                state = "running"
            elif label in running:
                state = "loaded"
            else:
                state = "unloaded"

            if disabled:
                state = "disabled"

            flags, sig = [], None
            if category in MONITORED:
                flags, sig = assess(plist, filepath, label, plist_args(plist),
                                    snap.get(filepath, {}), baseline.get(filepath))
            flags.sort(reverse=True)

            services.append({
                "risk": max((f[0] for f in flags), default=0),
                "flags": [f[1] for f in flags],
                "signer": sig,
                "label": label,
                "category": category,
                "state": state,
                "pid": pid,
                "exitStatus": status,
                "program": program,
                "runAtLoad": run_at_load,
                "keepAlive": keep_alive,
                "keepAliveDetail": str(keep_alive_detail) if keep_alive_detail else None,
                "disabled": disabled,
                "startInterval": start_interval,
                "startCalendar": str(start_calendar) if start_calendar else None,
                "watchPaths": watch_paths,
                "plistPath": filepath,
            })

    cron_jobs = collect_cron()
    services.extend(cron_jobs)

    removed = sorted(p for p in baseline if p not in snap)
    return {"services": services, "removed": removed}


def notify(msg):
    subprocess.run(["osascript", "-e", "on run argv", "-e",
                    'display notification (item 1 of argv) with title "launchd Viewer" sound name "Basso"',
                    "-e", "end run", msg], capture_output=True)


def monitor_loop():
    """Background watch: macOS notification when a risky/changed item or removal first appears."""
    seen = None
    while True:
        try:
            data = collect_data()
            snap = snapshot()
            current = {(s["plistPath"], json.dumps(snap.get(s["plistPath"])), f): s["label"]
                       for s in data["services"] if s.get("risk", 0) >= 2 for f in s["flags"]}
            current.update({("removed", p, ""): p for p in data["removed"]})
            if seen is not None:
                fresh = [k for k in current if k not in seen]
                for key in fresh[:5]:
                    notify(f"{current[key]}: {key[2] or 'plist が削除された'}")
                if len(fresh) > 5:
                    notify(f"他 {len(fresh) - 5} 件の警告")
            seen = current
        except Exception as e:
            print(f"monitor error: {e}", file=sys.stderr)
        time.sleep(MONITOR_INTERVAL)


def collect_cron():
    """Collect cron jobs for current user."""
    jobs = []
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0:
            for i, line in enumerate(result.stdout.strip().split("\n"), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 5)
                if len(parts) >= 6:
                    schedule = " ".join(parts[:5])
                    command = parts[5]
                    program = command.split(">>")[0].split(">")[0].split("|")[0].strip()
                    jobs.append({
                        "label": f"cron #{i}: {schedule}",
                        "category": "Cron",
                        "state": "loaded",
                        "pid": None,
                        "exitStatus": None,
                        "program": program,
                        "runAtLoad": False,
                        "keepAlive": False,
                        "keepAliveDetail": None,
                        "disabled": False,
                        "startInterval": None,
                        "startCalendar": schedule,
                        "watchPaths": None,
                        "plistPath": f"crontab -l (line {i})",
                        "cronLine": line,
                    })
    except Exception:
        pass
    return jobs


def action_stop(label, plist_path):
    """Stop/unload a launchd service."""
    r = subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        r = subprocess.run(["launchctl", "unload", plist_path],
                           capture_output=True, text=True)
    if r.returncode == 0:
        return {"ok": True, "message": f"Stopped {label}"}
    return {"ok": False, "message": r.stderr.strip() or "Failed to stop"}


def action_start(label, plist_path):
    """Start/load a launchd service."""
    r = subprocess.run(["launchctl", "load", plist_path],
                       capture_output=True, text=True)
    if r.returncode == 0:
        return {"ok": True, "message": f"Started {label}"}
    return {"ok": False, "message": r.stderr.strip() or "Failed to start"}


def action_delete_plist(label, plist_path):
    """Stop a service and delete its plist file."""
    if plist_path.startswith("/System/"):
        return {"ok": False, "message": "System plist cannot be deleted"}
    if not os.path.isfile(plist_path):
        return {"ok": False, "message": "Plist file not found"}
    # Stop first if loaded
    subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"],
                    capture_output=True, text=True)
    subprocess.run(["launchctl", "unload", plist_path],
                    capture_output=True, text=True)
    try:
        os.remove(plist_path)
        return {"ok": True, "message": f"Deleted {os.path.basename(plist_path)}"}
    except PermissionError:
        return {"ok": False, "message": "Permission denied — try running with sudo"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def action_delete_cron(cron_line):
    """Delete a specific cron job."""
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if result.returncode != 0:
        return {"ok": False, "message": "Failed to read crontab"}
    lines = result.stdout.strip().split("\n")
    new_lines = [l for l in lines if l.strip() != cron_line]
    if len(new_lines) == len(lines):
        return {"ok": False, "message": "Cron entry not found"}
    new_crontab = "\n".join(new_lines) + "\n" if new_lines else ""
    p = subprocess.run(["crontab", "-"], input=new_crontab, capture_output=True, text=True)
    if p.returncode == 0:
        return {"ok": True, "message": "Cron entry deleted"}
    return {"ok": False, "message": p.stderr.strip() or "Failed to update crontab"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress access logs

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            services = collect_data()
            html = HTML_TEMPLATE.replace("__DATA__", json.dumps(services, ensure_ascii=False))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())
        elif self.path == "/api/refresh":
            data = collect_data()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/api/action":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        action = body.get("action")
        label = body.get("label", "")
        plist_path = body.get("plistPath", "")
        cron_line = body.get("cronLine", "")
        category = body.get("category", "")

        result = {"ok": False, "message": "Unknown action"}

        if action == "stop":
            result = action_stop(label, plist_path)
        elif action == "start":
            result = action_start(label, plist_path)
        elif action == "delete_cron":
            result = action_delete_cron(cron_line)
        elif action == "delete_plist":
            result = action_delete_plist(label, plist_path)
        elif action == "accept_baseline":
            save_baseline(snapshot())
            result = {"ok": True, "message": "現在の状態をベースラインとして保存しました"}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<title>launchd Viewer</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }
.header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.header h1 { font-size: 20px; color: #f0f6fc; white-space: nowrap; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; }
.stat { background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 6px 12px; font-size: 13px; }
.stat .num { font-weight: 700; font-size: 16px; }
.stat.running .num { color: #3fb950; }
.stat.loaded .num { color: #58a6ff; }
.stat.unloaded .num { color: #8b949e; }
.stat.disabled .num { color: #f85149; }
.controls { padding: 12px 24px; background: #161b22; border-bottom: 1px solid #30363d; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
input[type="text"] { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; border-radius: 6px; font-size: 14px; width: 300px; }
input[type="text"]:focus { outline: none; border-color: #58a6ff; }
select { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 10px; border-radius: 6px; font-size: 13px; }
.filter-btn { background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 5px 12px; border-radius: 20px; font-size: 12px; cursor: pointer; transition: all 0.15s; }
.filter-btn:hover { border-color: #58a6ff; }
.filter-btn.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }
.main { padding: 16px 24px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead th { position: sticky; top: 0; background: #161b22; border-bottom: 2px solid #30363d; padding: 8px 10px; text-align: left; color: #8b949e; font-weight: 600; cursor: pointer; user-select: none; white-space: nowrap; }
thead th:hover { color: #f0f6fc; }
thead th .arrow { margin-left: 4px; font-size: 10px; }
thead th.no-sort { cursor: default; }
thead th.no-sort:hover { color: #8b949e; }
tbody tr { border-bottom: 1px solid #21262d; transition: background 0.1s; }
tbody tr:hover { background: #161b22; }
td { padding: 6px 10px; vertical-align: top; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td.label-cell { font-family: "SF Mono", Menlo, monospace; font-size: 12px; color: #58a6ff; }
td.program-cell { font-family: "SF Mono", Menlo, monospace; font-size: 11px; color: #8b949e; }
td.actions-cell { white-space: nowrap; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
.badge.running { background: #23312e; color: #3fb950; }
.badge.loaded { background: #1c2a3f; color: #58a6ff; }
.badge.unloaded { background: #1c1e21; color: #8b949e; }
.badge.disabled { background: #3d1a1e; color: #f85149; }
.badge.cat-user { background: #2d1f3d; color: #bc8cff; }
.badge.cat-global { background: #1c2a3f; color: #58a6ff; }
.badge.cat-system { background: #1f2d1f; color: #56d364; }
.badge.cat-cron { background: #2d2a1f; color: #e3b341; }
.badge.risk3 { background: #5a1d24; color: #ff7b72; }
.badge.risk2 { background: #3d2e1a; color: #e3b341; }
.badge.risk1 { background: #1c1e21; color: #8b949e; }
.stat.suspicious .num { color: #ff7b72; }
.alerts { margin: 12px 24px 0; padding: 10px 14px; border: 1px solid #f8514966; background: #2a1417; border-radius: 8px; font-size: 13px; }
.alerts ul { margin: 6px 0 0 20px; font-family: "SF Mono", Menlo, monospace; font-size: 12px; }
.flag3 { color: #ff7b72; } .flag2 { color: #e3b341; } .flag1 { color: #8b949e; }
.check { color: #3fb950; }
.cross { color: #484f58; }
.detail-row td { white-space: normal; word-break: break-all; background: #0d1117; padding: 12px 16px; font-size: 12px; }
.detail-content { font-family: "SF Mono", Menlo, monospace; line-height: 1.6; }
.detail-content dt { color: #8b949e; margin-top: 6px; }
.detail-content dd { color: #c9d1d9; margin-left: 16px; }
.hidden { display: none; }
.count-info { font-size: 13px; color: #8b949e; padding: 8px 0; }
.act-btn { padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer; border: 1px solid; transition: all 0.15s; margin-right: 4px; }
.act-btn.stop { background: #3d1a1e; color: #f85149; border-color: #f8514966; }
.act-btn.stop:hover { background: #5a1d24; }
.act-btn.start { background: #1a3d1e; color: #3fb950; border-color: #3fb95066; }
.act-btn.start:hover { background: #1d5a24; }
.act-btn.delete { background: #3d1a1e; color: #f85149; border-color: #f8514966; }
.act-btn.delete:hover { background: #5a1d24; }
.act-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.toast { position: fixed; bottom: 24px; right: 24px; padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 600; z-index: 999; transition: opacity 0.3s; }
.toast.success { background: #23312e; color: #3fb950; border: 1px solid #3fb95066; }
.toast.error { background: #3d1a1e; color: #f85149; border: 1px solid #f8514966; }
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 100; display: flex; align-items: center; justify-content: center; }
.modal { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; max-width: 480px; width: 90%; }
.modal h3 { color: #f0f6fc; margin-bottom: 12px; font-size: 16px; }
.modal p { color: #8b949e; margin-bottom: 16px; font-size: 13px; line-height: 1.5; }
.modal code { background: #0d1117; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #e3b341; }
.modal-actions { display: flex; gap: 8px; justify-content: flex-end; }
.modal-btn { padding: 6px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; border: 1px solid; }
.modal-btn.cancel { background: #21262d; color: #c9d1d9; border-color: #30363d; }
.modal-btn.cancel:hover { background: #30363d; }
.modal-btn.danger { background: #da3633; color: #fff; border-color: #da3633; }
.modal-btn.danger:hover { background: #b62324; }
.modal-btn.ok { background: #238636; color: #fff; border-color: #238636; }
.modal-btn.ok:hover { background: #2ea043; }
</style>
</head>
<body>
<div class="header">
  <h1>&#9881; launchd Viewer</h1>
  <div class="stats" id="stats"></div>
  <div style="margin-left:auto;display:flex;align-items:center;gap:8px;">
    <span id="updateIndicator" style="font-size:11px;color:#484f58;"></span>
    <button class="filter-btn" id="refreshBtn" title="Refresh now">Refresh</button>
    <label style="font-size:13px;color:#8b949e;display:flex;align-items:center;gap:4px;">
      <input type="checkbox" id="autoRefresh" checked> Auto (5s)
    </label>
  </div>
</div>
<div class="controls">
  <input type="text" id="search" placeholder="Filter by label or program...">
  <select id="categoryFilter">
    <option value="">All Categories</option>
    <option value="User Agents">User Agents</option>
    <option value="Global Agents">Global Agents</option>
    <option value="Global Daemons">Global Daemons</option>
    <option value="Cron">Cron</option>
    <option value="System Agents">System Agents</option>
    <option value="System Daemons">System Daemons</option>
  </select>
  <button class="filter-btn active" data-state="">All</button>
  <button class="filter-btn" data-state="running">Running</button>
  <button class="filter-btn" data-state="loaded">Loaded</button>
  <button class="filter-btn" data-state="unloaded">Unloaded</button>
  <button class="filter-btn" data-state="disabled">Disabled</button>
  <label style="font-size:13px;color:#8b949e;margin-left:12px;display:flex;align-items:center;gap:4px;">
    <input type="checkbox" id="hideApple" checked> Hide com.apple.*
  </label>
  <label style="font-size:13px;color:#8b949e;display:flex;align-items:center;gap:4px;">
    <input type="checkbox" id="hideSystem" checked> Hide System
  </label>
  <label style="font-size:13px;color:#ff7b72;display:flex;align-items:center;gap:4px;">
    <input type="checkbox" id="suspOnly"> Suspicious only
  </label>
</div>
 <div id="alerts"></div>
<div class="main">
  <div class="count-info" id="countInfo"></div>
  <table>
    <thead>
      <tr>
        <th class="no-sort">Actions</th>
        <th data-col="risk">Risk <span class="arrow">&#9660;</span></th>
        <th data-col="state">State <span class="arrow"></span></th>
        <th data-col="category">Category <span class="arrow"></span></th>
        <th data-col="label">Label <span class="arrow"></span></th>
        <th data-col="pid">PID <span class="arrow"></span></th>
        <th data-col="exitStatus">Exit <span class="arrow"></span></th>
        <th data-col="runAtLoad">RunAtLoad <span class="arrow"></span></th>
        <th data-col="keepAlive">KeepAlive <span class="arrow"></span></th>
        <th data-col="program">Program <span class="arrow"></span></th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
</div>
<div id="modalContainer"></div>
<div id="toastContainer"></div>
<script>
let DATA = __DATA__.services;
let REMOVED = __DATA__.removed;
let suspOnly = false;
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const RISK = ["", "low", "medium", "high"];

let sortCol = "risk";
let sortAsc = false;
let stateFilter = "";
let catFilter = "";
let searchQuery = "";
let expandedLabel = null;
let hideApple = true;
let hideSystem = true;

function catClass(c) {
  if (c.startsWith("User")) return "cat-user";
  if (c.startsWith("System")) return "cat-system";
  if (c === "Cron") return "cat-cron";
  return "cat-global";
}

function showToast(msg, type) {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById("toastContainer").appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 300); }, 2500);
}

function showModal(title, message, onConfirm, btnClass) {
  const container = document.getElementById("modalContainer");
  container.innerHTML = `<div class="modal-overlay" id="modalOverlay">
    <div class="modal">
      <h3>${title}</h3>
      <p>${message}</p>
      <div class="modal-actions">
        <button class="modal-btn cancel" id="modalCancel">Cancel</button>
        <button class="modal-btn ${btnClass || 'danger'}" id="modalConfirm">OK</button>
      </div>
    </div>
  </div>`;
  document.getElementById("modalCancel").onclick = () => { container.innerHTML = ""; };
  document.getElementById("modalOverlay").onclick = (e) => { if (e.target === e.currentTarget) container.innerHTML = ""; };
  document.getElementById("modalConfirm").onclick = () => { container.innerHTML = ""; onConfirm(); };
}

async function apiAction(body) {
  const res = await fetch("/api/action", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) });
  const data = await res.json();
  showToast(data.message, data.ok ? "success" : "error");
  if (data.ok) await refreshData();
}

async function refreshData() {
  const res = await fetch("/api/refresh");
  const d = await res.json();
  DATA = d.services; REMOVED = d.removed;
  renderStats();
  render();
}

function handleAction(e) {
  e.stopPropagation();
  const btn = e.target.closest(".act-btn");
  if (!btn) return;
  const action = btn.dataset.action;
  const idx = parseInt(btn.dataset.idx);
  const s = sorted(filtered())[idx];
  if (!s) return;

  if (action === "stop") {
    showModal("Stop Service", `<code>${esc(s.label)}</code> を停止しますか？`, () => {
      apiAction({ action: "stop", label: s.label, plistPath: s.plistPath });
    });
  } else if (action === "start") {
    showModal("Start Service", `<code>${esc(s.label)}</code> を起動しますか？`, () => {
      apiAction({ action: "start", label: s.label, plistPath: s.plistPath });
    }, "ok");
  } else if (action === "delete_cron") {
    showModal("Delete Cron Job", `このcronエントリを削除しますか？<br><code>${esc(s.cronLine)}</code>`, () => {
      apiAction({ action: "delete_cron", cronLine: s.cronLine });
    });
  } else if (action === "delete_plist") {
    showModal("Delete Plist", `<code>${esc(s.plistPath)}</code><br><br>このplistファイルを削除しますか？サービスは先に停止されます。この操作は取り消せません。`, () => {
      apiAction({ action: "delete_plist", label: s.label, plistPath: s.plistPath });
    });
  }
}

function renderStats() {
  const counts = { running: 0, loaded: 0, unloaded: 0, disabled: 0 };
  DATA.forEach(s => counts[s.state] = (counts[s.state] || 0) + 1);
  document.getElementById("stats").innerHTML =
    `<div class="stat"><span class="num">${DATA.length}</span> Total</div>` +
    Object.entries(counts).map(([k, v]) =>
      `<div class="stat ${k}"><span class="num">${v}</span> ${k.charAt(0).toUpperCase() + k.slice(1)}</div>`
    ).join("") +
    `<div class="stat suspicious"><span class="num">${DATA.filter(s => s.risk >= 2).length}</span> Suspicious</div>`;
  const diff = DATA.filter(s => (s.flags || []).some(f => f.includes("ベースライン")));
  const el = document.getElementById("alerts");
  if (!diff.length && !REMOVED.length) { el.innerHTML = ""; return; }
  el.innerHTML = `<div class="alerts"><b>ベースラインとの差分</b>（新規・変更 ${diff.length} / 削除 ${REMOVED.length}）
    <button class="act-btn start" id="acceptBtn" style="margin-left:8px">現状をベースラインとして承認</button>
    <ul>${diff.map(s => `<li>${esc(s.label)} — ${esc(s.flags.filter(f => f.includes("ベースライン")).join(" / "))}</li>`).join("")}
    ${REMOVED.map(p => `<li>削除: ${esc(p)}</li>`).join("")}</ul></div>`;
  document.getElementById("acceptBtn").onclick = () => showModal("Accept Baseline",
    "現在の plist と実行ファイルの状態を正常としてベースラインに保存します。差分の中身を確認してから承認してください。",
    () => apiAction({ action: "accept_baseline" }), "ok");
}

function filtered() {
  return DATA.filter(s => {
    if (suspOnly && !(s.risk >= 2)) return false;
    if (hideApple && s.label.startsWith("com.apple.") && !(s.risk >= 2)) return false;
    if (hideSystem && (s.category === "System Agents" || s.category === "System Daemons")) return false;
    if (stateFilter && s.state !== stateFilter) return false;
    if (catFilter && s.category !== catFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (!s.label.toLowerCase().includes(q) && !(s.program || "").toLowerCase().includes(q)) return false;
    }
    return true;
  });
}

function sorted(list) {
  return [...list].sort((a, b) => {
    let va = a[sortCol], vb = b[sortCol];
    if (va == null) va = "";
    if (vb == null) vb = "";
    if (typeof va === "boolean") { va = va ? 1 : 0; vb = vb ? 1 : 0; }
    if (typeof va === "number" && typeof vb === "number") return sortAsc ? va - vb : vb - va;
    return sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
  });
}

function actionButtons(s, idx) {
  if (s.category === "Cron") {
    return `<button class="act-btn delete" data-action="delete_cron" data-idx="${idx}" title="Delete cron entry">Delete</button>`;
  }
  const isSystem = s.category.startsWith("System");
  let btns = "";
  if (s.state === "running" || s.state === "loaded") {
    btns += `<button class="act-btn stop" data-action="stop" data-idx="${idx}" ${isSystem ? 'disabled title="System service"' : 'title="Stop service"'}>Stop</button>`;
  } else {
    btns += `<button class="act-btn start" data-action="start" data-idx="${idx}" ${isSystem ? 'disabled title="System service"' : 'title="Start service"'}>Start</button>`;
  }
  if (!isSystem) {
    btns += `<button class="act-btn delete" data-action="delete_plist" data-idx="${idx}" title="Delete plist file">Del</button>`;
  }
  return btns;
}

function render() {
  const list = sorted(filtered());
  document.getElementById("countInfo").textContent = `${list.length} / ${DATA.length} services`;
  const tbody = document.getElementById("tbody");
  let html = "";
  for (let i = 0; i < list.length; i++) {
    const s = list[i];
    html += `<tr class="svc-row" data-label="${esc(s.label)}">
      <td class="actions-cell">${actionButtons(s, i)}</td>
      <td>${s.risk ? `<span class="badge risk${s.risk}" title="${esc((s.flags || []).join("\\n"))}">${RISK[s.risk]}</span>` : '<span class="cross">-</span>'}</td>
      <td><span class="badge ${s.state}">${s.state}</span></td>
      <td><span class="badge ${catClass(s.category)}">${esc(s.category)}</span></td>
      <td class="label-cell">${esc(s.label)}</td>
      <td>${s.pid != null ? s.pid : "-"}</td>
      <td>${s.exitStatus != null ? s.exitStatus : "-"}</td>
      <td>${s.runAtLoad ? '<span class="check">&#10003;</span>' : '<span class="cross">-</span>'}</td>
      <td>${s.keepAlive ? '<span class="check">&#10003;</span>' : '<span class="cross">-</span>'}</td>
      <td class="program-cell" title="${esc(s.program)}">${esc(s.program || "-")}</td>
    </tr>`;
    if (expandedLabel === s.label) {
      html += `<tr class="detail-row"><td colspan="10"><dl class="detail-content">
        ${(s.flags || []).length ? `<dt>Red flags</dt>${s.flags.map(f => `<dd class="flag${s.risk}">• ${esc(f)}</dd>`).join("")}` : ""}
        ${s.signer ? `<dt>Code Signature</dt><dd>${esc(s.signer)}</dd>` : ""}
        <dt>Plist Path</dt><dd>${esc(s.plistPath)}</dd>
        <dt>Program</dt><dd>${esc(s.program || "N/A")}</dd>
        ${s.keepAliveDetail ? `<dt>KeepAlive Detail</dt><dd>${esc(s.keepAliveDetail)}</dd>` : ""}
        ${s.startInterval ? `<dt>StartInterval</dt><dd>${esc(s.startInterval)}s</dd>` : ""}
        ${s.startCalendar ? `<dt>StartCalendarInterval</dt><dd>${esc(s.startCalendar)}</dd>` : ""}
        ${s.watchPaths ? `<dt>WatchPaths</dt><dd>${esc(JSON.stringify(s.watchPaths))}</dd>` : ""}
        ${s.cronLine ? `<dt>Cron Line</dt><dd>${esc(s.cronLine)}</dd>` : ""}
      </dl></td></tr>`;
    }
  }
  tbody.innerHTML = html;
}

document.getElementById("hideApple").addEventListener("change", e => { hideApple = e.target.checked; render(); });
document.getElementById("suspOnly").addEventListener("change", e => { suspOnly = e.target.checked; render(); });
document.getElementById("hideSystem").addEventListener("change", e => { hideSystem = e.target.checked; render(); });
document.getElementById("search").addEventListener("input", e => { searchQuery = e.target.value; render(); });
document.getElementById("categoryFilter").addEventListener("change", e => { catFilter = e.target.value; render(); });
document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    stateFilter = btn.dataset.state;
    render();
  });
});
document.querySelectorAll("thead th[data-col]").forEach(th => {
  th.addEventListener("click", () => {
    const col = th.dataset.col;
    if (sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = true; }
    document.querySelectorAll("thead th .arrow").forEach(a => a.textContent = "");
    th.querySelector(".arrow").textContent = sortAsc ? "\\u25B2" : "\\u25BC";
    render();
  });
});
document.getElementById("tbody").addEventListener("click", e => {
  if (e.target.closest(".act-btn")) { handleAction(e); return; }
  const row = e.target.closest(".svc-row");
  if (!row) return;
  const label = row.dataset.label;
  expandedLabel = expandedLabel === label ? null : label;
  render();
});

let autoRefreshEnabled = true;
let refreshTimer = null;

async function autoRefresh() {
  if (!autoRefreshEnabled) return;
  try {
    const res = await fetch("/api/refresh");
    const d = await res.json();
    const changed = JSON.stringify(d) !== JSON.stringify({services: DATA, removed: REMOVED});
    DATA = d.services; REMOVED = d.removed;
    if (changed) { renderStats(); render(); }
    const now = new Date();
    document.getElementById("updateIndicator").textContent = `Updated ${now.toLocaleTimeString()}`;
  } catch(e) {
    document.getElementById("updateIndicator").textContent = "Update failed";
  }
  refreshTimer = setTimeout(autoRefresh, 5000);
}

document.getElementById("refreshBtn").addEventListener("click", async () => {
  await refreshData();
  const now = new Date();
  document.getElementById("updateIndicator").textContent = `Updated ${now.toLocaleTimeString()}`;
});
document.getElementById("autoRefresh").addEventListener("change", e => {
  autoRefreshEnabled = e.target.checked;
  if (autoRefreshEnabled) { autoRefresh(); } else { clearTimeout(refreshTimer); }
});

renderStats();
render();
autoRefresh();
</script>
</body>
</html>"""

PORT = 8745

def main():
    print("Collecting launchd data...")
    data = collect_data()
    print(f"Found {len(data['services'])} services, "
          f"{sum(s.get('risk', 0) >= 2 for s in data['services'])} suspicious (baseline: {BASELINE_PATH})")
    threading.Thread(target=monitor_loop, daemon=True).start()

    def handler(sig, frame):
        print("\nShutting down...")
        sys.exit(0)
    signal.signal(signal.SIGINT, handler)

    server = HTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"Server running at {url}")
    webbrowser.open(url)
    server.serve_forever()


if __name__ == "__main__":
    main()
