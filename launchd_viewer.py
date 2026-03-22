#!/usr/bin/env python3
"""launchd configuration viewer - macOS launchd services visualizer"""

import json
import os
import plistlib
import subprocess
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import tempfile
import signal
import sys
import urllib.parse

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


def collect_data():
    """Collect all launchd data."""
    running = get_launchctl_list()
    services = []

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

            services.append({
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

    return services


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


# Global reference to generated HTML
generated_html = ""


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
</div>
<div class="main">
  <div class="count-info" id="countInfo"></div>
  <table>
    <thead>
      <tr>
        <th class="no-sort">Actions</th>
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
let DATA = __DATA__;

let sortCol = "label";
let sortAsc = true;
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
  DATA = await res.json();
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
    showModal("Stop Service", `<code>${s.label}</code> を停止しますか？`, () => {
      apiAction({ action: "stop", label: s.label, plistPath: s.plistPath });
    });
  } else if (action === "start") {
    showModal("Start Service", `<code>${s.label}</code> を起動しますか？`, () => {
      apiAction({ action: "start", label: s.label, plistPath: s.plistPath });
    }, "ok");
  } else if (action === "delete_cron") {
    showModal("Delete Cron Job", `このcronエントリを削除しますか？<br><code>${s.cronLine || ''}</code>`, () => {
      apiAction({ action: "delete_cron", cronLine: s.cronLine });
    });
  } else if (action === "delete_plist") {
    showModal("Delete Plist", `<code>${s.plistPath}</code><br><br>このplistファイルを削除しますか？サービスは先に停止されます。この操作は取り消せません。`, () => {
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
    ).join("");
}

function filtered() {
  return DATA.filter(s => {
    if (hideApple && s.label.startsWith("com.apple.")) return false;
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
    html += `<tr class="svc-row" data-label="${s.label}">
      <td class="actions-cell">${actionButtons(s, i)}</td>
      <td><span class="badge ${s.state}">${s.state}</span></td>
      <td><span class="badge ${catClass(s.category)}">${s.category}</span></td>
      <td class="label-cell">${s.label}</td>
      <td>${s.pid != null ? s.pid : "-"}</td>
      <td>${s.exitStatus != null ? s.exitStatus : "-"}</td>
      <td>${s.runAtLoad ? '<span class="check">&#10003;</span>' : '<span class="cross">-</span>'}</td>
      <td>${s.keepAlive ? '<span class="check">&#10003;</span>' : '<span class="cross">-</span>'}</td>
      <td class="program-cell" title="${s.program || ''}">${s.program || "-"}</td>
    </tr>`;
    if (expandedLabel === s.label) {
      html += `<tr class="detail-row"><td colspan="9"><dl class="detail-content">
        <dt>Plist Path</dt><dd>${s.plistPath}</dd>
        <dt>Program</dt><dd>${s.program || "N/A"}</dd>
        ${s.keepAliveDetail ? `<dt>KeepAlive Detail</dt><dd>${s.keepAliveDetail}</dd>` : ""}
        ${s.startInterval ? `<dt>StartInterval</dt><dd>${s.startInterval}s</dd>` : ""}
        ${s.startCalendar ? `<dt>StartCalendarInterval</dt><dd>${s.startCalendar}</dd>` : ""}
        ${s.watchPaths ? `<dt>WatchPaths</dt><dd>${JSON.stringify(s.watchPaths)}</dd>` : ""}
        ${s.cronLine ? `<dt>Cron Line</dt><dd>${s.cronLine}</dd>` : ""}
      </dl></td></tr>`;
    }
  }
  tbody.innerHTML = html;
}

document.getElementById("hideApple").addEventListener("change", e => { hideApple = e.target.checked; render(); });
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
    const newData = await res.json();
    const changed = JSON.stringify(newData) !== JSON.stringify(DATA);
    DATA = newData;
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
    global generated_html
    print("Collecting launchd data...")
    services = collect_data()
    print(f"Found {len(services)} services")

    generated_html = HTML_TEMPLATE.replace("__DATA__", json.dumps(services, ensure_ascii=False))

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
