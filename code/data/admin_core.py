from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import threading
import time
from typing import TYPE_CHECKING

#utils
from utils.formatting import fmt
from utils.ip_utils import *
from utils.admin_config import *
from utils.admin_auth import *
from utils.admin_login import *
from utils.http_helpers import *
from utils.upload_control import (
    _cancelled_paths, _upload_cooldowns, COOLDOWN_SECONDS,
    is_path_cancelled, is_ip_on_cooldown, set_ip_cooldown, cancel_upload_path
)
from utils.strict_mode import (
    STRICT_MODE, STRICT_RAM_LIMIT,
    get_strict_mode, set_strict_mode, add_to_strict_queue,
    remove_from_strict_queue, get_strict_queue_snapshot, get_strict_entry
)

if TYPE_CHECKING:
    from server import ModernHandler  

# Module-level references to server globals 
# Populated by init() once server.py has finished building its own globals. 
_g: dict = {}

def init(server_globals: dict) -> None:
    global _g
    _g = server_globals
    load_admin_config(
        base_file=_g.get("__file__", "server.py"),
        admin_password=_g.get("ADMIN_PASSWORD", "change_me"),
        base_excluded_extensions=_g.get("EXCLUDED_EXTENSIONS", set()),
    )
   
    set_password_hash(_g.get("ADMIN_PASSWORD", "change_me"))

_admin_config_lock = threading.Lock()

def is_localhost(handler) -> bool:
    client_ip = handler.client_address[0]
    if is_loopback(client_ip):
        return True
    if hasattr(handler, "is_admin") and handler.is_admin():
        return True
    local_ip = _g.get("get_local_ip", lambda: "")()
    if local_ip and client_ip == local_ip:
        return True
    return False

def check_access(handler) -> bool:
   
    client_ip = handler.client_address[0]
    handler.update_active_user(client_ip)
    try:
        Sip = ipaddress.ip_address(client_ip)
        if is_loopback(client_ip):
            return True
        if client_ip in BANNED_IPS:
            return False
        return any(Sip in network for network in ALLOWED_NETWORKS)
    except ValueError:
        return False

def _serve_admin_html(handler) -> None:
    # Serve admin.html
    admin_html_path = os.path.join(
        os.path.dirname(os.path.abspath(_g.get("__file__", "server.py"))),
        "admin.html",
    )
    try:
        with open(admin_html_path, "rb") as f:
            body = f.read()
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        handler.wfile.write(body)
    except OSError:
        send_admin_error(handler, 404, "admin.html not found. Place it next to server.py.")


def _redirect_to_login(handler) -> None:
    handler.send_response(302)
    handler.send_header("Location", "/admin/login")
    handler.end_headers()

# A: Access & Perimeter Control

def handle_admin_network_add(handler, body: dict) -> None:
    subnet_str = body.get("subnet", "").strip()
    note       = body.get("note", "").strip()[:200]
    if not subnet_str:
        send_admin_error(handler, 400, "Field 'subnet' is required.")
        return
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError as e:
        send_admin_error(handler, 400, f"Invalid subnet: {e}")
        return
    if network.prefixlen < 8:
        send_admin_error(handler, 400,
            f"Subnet /{network.prefixlen} is too broad. Minimum prefix length is /8.")
        return
    if network in ALLOWED_NETWORKS:
        send_admin_error(handler, 409, f"Subnet {network} is already in the allowlist.")
        return
    ALLOWED_NETWORKS.append(network)
    if note:
        admin_notes[f"network:{network}"] = note
    write_admin_config()
    send_admin_ok(handler, {
        "added": str(network),
        "total": len(ALLOWED_NETWORKS),
        "networks": [str(n) for n in ALLOWED_NETWORKS],
    })
    print(f"[Admin] Subnet added: {network} note={note!r}")


def handle_admin_network_remove(handler, body: dict) -> None:
    subnet_str = body.get("subnet", "").strip()
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError as e:
        send_admin_error(handler, 400, f"Invalid subnet: {e}")
        return
    if network not in ALLOWED_NETWORKS:
        send_admin_error(handler, 404, f"Subnet {network} not in allowlist.")
        return
    ALLOWED_NETWORKS.remove(network)
    admin_notes.pop(f"network:{network}", None)
    write_admin_config()
    send_admin_ok(handler, {
        "removed": str(network),
        "total": len(ALLOWED_NETWORKS),
        "networks": [str(n) for n in ALLOWED_NETWORKS],
    })
    print(f"[Admin] Subnet removed: {network}")


def handle_admin_killswitch(handler, body: dict) -> None:
    if body.get("confirm") != "KILL":
        send_admin_error(handler, 400,
            'Kill switch requires body: {"confirm": "KILL"}. '
            "This is not an accident prevention — it is a protocol requirement.")
        return
    previous_count = len(ALLOWED_NETWORKS)
    # Snapshot the current allowlist so the kill switch can be reverted later.
    previous_networks.clear()
    previous_networks.extend(ALLOWED_NETWORKS)
    ALLOWED_NETWORKS.clear()
    write_admin_config()
    _sse_broadcast = _g.get("sse_broadcast")
    if _sse_broadcast:
        _sse_broadcast("admin_event", {
            "type": "lockdown",
            "message": "Server has entered lockdown mode.",
        })
    send_admin_ok(handler, {
        "status": "lockdown_active",
        "cleared": previous_count,
        "networks": [],
        "message": "All subnets cleared. Server is now localhost-only.",
    })
    print(f"[Admin] KILL SWITCH ACTIVATED, {previous_count} networks cleared.")


def handle_admin_killswitch_off(handler, body: dict) -> None:
    """Revert the kill switch: restore the subnets that were backed up when
    the kill switch was activated."""
    if not previous_networks:
        send_admin_error(handler, 400,
            "No previous networks to restore. The kill switch was never activated "
            "or the backup is empty.")
        return

    restored = [str(n) for n in previous_networks]
    ALLOWED_NETWORKS.clear()
    ALLOWED_NETWORKS.extend(previous_networks)
    previous_networks.clear()
    write_admin_config()

    _sse_broadcast = _g.get("sse_broadcast")
    if _sse_broadcast:
        _sse_broadcast("admin_event", {
            "type": "lockdown_off",
            "message": "Kill switch disabled. Networks restored.",
        })

    send_admin_ok(handler, {
        "status": "lockdown_off",
        "restored": restored,
        "networks": [str(n) for n in ALLOWED_NETWORKS],
        "message": f"Kill switch disabled. Restored {len(restored)} networks.",
    })
    print(f"[Admin] KILL SWITCH DISABLED, {len(restored)} networks restored.")


# Section B: User & Connection Management

def handle_admin_radar(handler) -> None:
    active_users      = _g.get("active_users", {})
    active_users_lock = _g.get("active_users_lock", threading.Lock())
    _sse_clients      = _g.get("_sse_clients", {})
    _sse_clients_lock = _g.get("_sse_clients_lock", threading.Lock())

    now = time.time()
    with active_users_lock:
        snapshot = dict(active_users)
    with _sse_clients_lock:
        sse_connected_ips = {cid.rsplit(":", 1)[0] for cid in _sse_clients}

    users = []
    for ip, last_seen in snapshot.items():
        try:
            is_loop = is_loopback(ip)
        except ValueError:
            is_loop = False

        # An IP is "external" when it is not loopback and does not belong to
        # any of the allowed subnets — i.e. it would be blocked by check_access.
        try:
            Sip = ipaddress.ip_address(ip)
            is_external = (not is_loop) and not any(
                Sip in network for network in ALLOWED_NETWORKS
            )
        except ValueError:
            is_external = False

        users.append({
            "ip":          ip,
            "last_seen_s": round(now - last_seen, 1),
            "last_seen_ts": datetime.datetime.fromtimestamp(last_seen).strftime("%H:%M:%S"),
            "sse_active":  ip in sse_connected_ips,
            "banned":      ip in BANNED_IPS,
            "is_loopback": is_loop,
            "is_external": is_external,
        })
    users.sort(key=lambda u: u["last_seen_s"])
    send_admin_ok(handler, {
        "users":       users,
        "total":       len(users),
        "sse_count":   len(sse_connected_ips),
        "banned_ips":  sorted(BANNED_IPS),
        "timestamp":   datetime.datetime.now().isoformat(),
    })


def handle_admin_ban(handler, body: dict) -> None:
    target_ip = body.get("ip", "").strip()
    note      = body.get("note", "").strip()[:500]
    try:
        parsed = is_loopback(target_ip)
    except ValueError:
        send_admin_error(handler, 400, f"Invalid IP address: {target_ip!r}")
        return
    if parsed:
        send_admin_error(handler, 403,
            "Cannot ban server.")
        return

    BANNED_IPS.add(target_ip)
    if note:
        admin_notes[target_ip] = (
            f"Banned {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} — {note}"
        )
    write_admin_config()

    active_users      = _g.get("active_users", {})
    active_users_lock = _g.get("active_users_lock", threading.Lock())
    _sse_clients      = _g.get("_sse_clients", {})
    _sse_clients_lock = _g.get("_sse_clients_lock", threading.Lock())

    with active_users_lock:
        active_users.pop(target_ip, None)

    evicted_ids = []
    _sse_send_to = _g.get("sse_send_to")
    with _sse_clients_lock:
        target_cids = [cid for cid, info in _sse_clients.items() if info.get("ip") == target_ip]

    for cid in target_cids:
        try:
            delivered = _sse_send_to(cid, "banned", {"reason": "You have been banned."}) if _sse_send_to else False
            if delivered:
                evicted_ids.append(cid)
        except Exception:
            pass

    send_admin_ok(handler, {
        "banned":        target_ip,
        "note":          note,
        "sse_evicted":   len(evicted_ids),
        "total_banned":  len(BANNED_IPS),
    })
    print(f"[Admin] Banned: {target_ip}  reason={note!r}")


def handle_admin_unban(handler, body: dict) -> None:
    target_ip = body.get("ip", "").strip()
    if target_ip not in BANNED_IPS:
        send_admin_error(handler, 404, f"IP {target_ip!r} is not in the ban list.")
        return
    BANNED_IPS.discard(target_ip)
    admin_notes.pop(target_ip, None)
    write_admin_config()
    send_admin_ok(handler, {
        "unbanned":     target_ip,
        "total_banned": len(BANNED_IPS),
    })
    print(f"[Admin] Unbanned: {target_ip}")


#  Section C: Data & Storage Moderation

def handle_admin_clipboard_wipe(handler, body: dict) -> None:
    clipboard_messages = _g.get("clipboard_messages", [])
    clipboard_lock     = _g.get("clipboard_lock", threading.Lock())
    _sse_broadcast     = _g.get("sse_broadcast")

    with clipboard_lock:
        previous_count = len(clipboard_messages)
        clipboard_messages.clear()

    if _sse_broadcast:
        _sse_broadcast("clipboard_wipe", {
            "wiped_by":  "admin",
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "message":   "Chat history cleared by the administrator.",
        })

    send_admin_ok(handler, {
        "wiped":   previous_count,
        "message": f"Cleared {previous_count} messages and notified all clients.",
    })
    print(f"[Admin] Clipboard wiped")


def handle_admin_storage(handler) -> None:
    folder = _g.get("FOLDER_TO_SERVE", ".")
    try:
        usage       = shutil.disk_usage(folder)
        folder_size = 0
        file_count  = 0
        for root, dirs, files in os.walk(folder):
            for fname in files:
                try:
                    folder_size += os.path.getsize(os.path.join(root, fname))
                    file_count  += 1
                except OSError:
                    pass

        send_admin_ok(handler, {
            "partition": {
                "total_bytes": usage.total,
                "used_bytes":  usage.used,
                "free_bytes":  usage.free,
                "used_pct":    round(usage.used / usage.total * 100, 1),
                "total_fmt":   fmt(usage.total),
                "used_fmt":    fmt(usage.used),
                "free_fmt":    fmt(usage.free),
            },
            "served_folder": {
                "path":       folder,
                "size_bytes": folder_size,
                "size_fmt":   fmt(folder_size),
                "file_count": file_count,
            },
        })
    except Exception as e:
        send_admin_error(handler, 500, f"Storage query failed: {e}")


# Section D: Traffic & Diagnostics

def handle_admin_ratelimit_status(handler) -> None:
    rate_limiter = _g.get("rate_limiter")
    RATE_LIMIT_WINDOW        = _g.get("RATE_LIMIT_WINDOW", 60)
    RATE_LIMIT_MAX_REQUESTS  = _g.get("RATE_LIMIT_MAX_REQUESTS", 200)

    if rate_limiter is None:
        send_admin_error(handler, 500, "rate_limiter not found in server globals.")
        return

    now     = time.time()
    entries = []
    with rate_limiter.lock:
        for ip, timestamps in rate_limiter.requests.items():
            recent = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
            if not recent:
                continue
            entries.append({
                "ip":                 ip,
                "requests_in_window": len(recent),
                "limit":              RATE_LIMIT_MAX_REQUESTS,
                "window_s":           RATE_LIMIT_WINDOW,
                "utilisation_pct":    round(len(recent) / RATE_LIMIT_MAX_REQUESTS * 100, 1),
                "oldest_request":     round(now - min(recent), 1),
                "newest_request":     round(now - max(recent), 1),
                "at_limit":           len(recent) >= RATE_LIMIT_MAX_REQUESTS,
                "banned":             ip in BANNED_IPS,
            })
    entries.sort(key=lambda e: e["requests_in_window"], reverse=True)
    send_admin_ok(handler, {
        "entries":        entries,
        "total_tracked":  len(entries),
        "window_s":       RATE_LIMIT_WINDOW,
        "limit":          RATE_LIMIT_MAX_REQUESTS,
        "at_limit_count": sum(1 for e in entries if e["at_limit"]),
    })


def handle_admin_ratelimit_reset(handler, body: dict) -> None:
    rate_limiter = _g.get("rate_limiter")
    if rate_limiter is None:
        send_admin_error(handler, 500, "rate_limiter not found in server globals.")
        return

    target = body.get("ip", "").strip()
    with rate_limiter.lock:
        if target == "ALL":
            cleared = len(rate_limiter.requests)
            rate_limiter.requests.clear()
        elif target in rate_limiter.requests:
            del rate_limiter.requests[target]
            cleared = 1
        else:
            send_admin_error(handler, 404, f"No rate limit data for IP: {target!r}")
            return

    send_admin_ok(handler, {"reset": target, "cleared": cleared})
    print(f"[Admin] Rate limit reset for: {target}")


def handle_admin_upload_locks(handler) -> None:
    ModernHandler = _g.get("ModernHandler")
    if ModernHandler is None:
        send_admin_error(handler, 500, "ModernHandler not available.")
        return

    locks_meta      = getattr(ModernHandler, "_chunk_locks", {})
    locks_meta_lock = getattr(ModernHandler, "_chunk_locks_meta", threading.Lock())

    now = time.time()
    with locks_meta_lock:
        lock_entries = []
        for path, lock_info in locks_meta.items():
            uip      = lock_info.get("uploader_ip", "")
            on_cd, cd_left = is_ip_on_cooldown(uip) if uip else (False, 0)
            exists   = os.path.exists(path)
            partial  = os.path.getsize(path) if exists else 0
            total_b  = lock_info.get("total_bytes", 0)
            lock_entries.append({
                "path":               path,
                "filename":           os.path.basename(path),
                "uploader_ip":        uip,
                "currently_writing":  lock_info["lock"].locked(),
                "exists_on_disk":     exists,
                "partial_size":       partial,
                "total_bytes":        total_b,
                "idle_seconds":       round(now - lock_info["last_active"], 1),
                "on_cooldown":        on_cd,
                "cooldown_secs_left": cd_left,
            })

    send_admin_ok(handler, {"active_locks": lock_entries, "count": len(lock_entries)})

def _do_cancel_upload(target_path: str) -> None:
  
    cancel_upload_path(
        target_path,
        modern_handler_class=_g.get("ModernHandler"),
        sse_broadcast_fn=_g.get("sse_broadcast"),
    )

    # Delete the partial file.
    try:
        if os.path.exists(target_path):
            os.remove(target_path)
    except OSError as e:
        print(f"[Admin] Warning: could not delete partial file {target_path}: {e}")

    # Tell the uploading client to abort immediately.
    _sse_broadcast = _g.get("sse_broadcast")
    if _sse_broadcast:
        _sse_broadcast("admin_cancel_upload", {"filename": os.path.basename(target_path)})


def handle_admin_upload_cancel(handler, body: dict) -> None:
    target_path = body.get("path", "").strip()
    if not target_path:
        send_admin_error(handler, 400, "Path is required.")
        return

    _do_cancel_upload(target_path)
    send_admin_ok(handler, {"canceled": target_path})
    print(f"[Admin] Cancelled upload: {target_path}")


def handle_admin_upload_cooldown(handler, body: dict) -> None:
    """Cancel the upload AND place the uploader's IP in a 5-minute cooldown."""
    target_path = body.get("path", "").strip()
    uploader_ip = body.get("ip", "").strip()

    if not target_path:
        send_admin_error(handler, 400, "Path is required.")
        return
    if not uploader_ip:
        send_admin_error(handler, 400, "Uploader IP is required.")
        return

    # Validate IP to prevent injection into the cooldown table.
    try:
        ipaddress.ip_address(uploader_ip)
    except ValueError:
        send_admin_error(handler, 400, f"Invalid IP address: {uploader_ip!r}")
        return

    # Cancel the upload (blacklist path + delete + SSE broadcast).
    _do_cancel_upload(target_path)

    # Place the uploader's IP in a cooldown period.
    set_ip_cooldown(uploader_ip)
    expiry = time.time() + COOLDOWN_SECONDS

    _sse_broadcast = _g.get("sse_broadcast")
    if _sse_broadcast:
        _sse_broadcast("admin_upload_cooldown", {
            "ip":            uploader_ip,
            "filename":      os.path.basename(target_path),
            "cooldown_secs": COOLDOWN_SECONDS,
        })

    send_admin_ok(handler, {
        "canceled":      target_path,
        "cooldown_ip":   uploader_ip,
        "cooldown_until": datetime.datetime.fromtimestamp(expiry).strftime("%H:%M:%S"),
    })
    print(f"[Admin] Cooldown applied to {uploader_ip} until "
          f"{datetime.datetime.fromtimestamp(expiry).strftime('%H:%M:%S')} "
          f"(upload: {target_path})")

# Section C: Exclusion Management

def handle_admin_exclusions_get(handler) -> None:
    send_admin_ok(handler, {
        "excluded_paths": sorted(EXCLUDED_PATHS),
        "excluded_extensions": sorted(EXCLUDED_EXTENSIONS),
    })


def _broadcast_exclusion_change(action: str, kind: str, value: str) -> None:
    """Notify any open admin dashboards so their exclusion window stays live,
    e.g. when a file/folder is excluded from the file-browser context menu
    while the exclusions modal is open in another tab."""
    _sse_broadcast = _g.get("sse_broadcast")
    if _sse_broadcast:
        _sse_broadcast("exclusion_change", {
            "action": action,        # "added" | "removed"
            "kind": kind,            # "path" | "extension"
            "value": value,
            "excluded_paths": sorted(EXCLUDED_PATHS),
            "excluded_extensions": sorted(EXCLUDED_EXTENSIONS),
        })


def handle_admin_exclusion_path_add(handler, body: dict) -> None:
    norm = normalize_path(body.get("path", ""))
    if not norm:
        send_admin_error(handler, 400, "Field 'path' is required.")
        return
    if norm in EXCLUDED_PATHS:
        # Already excluded — safe/idempotent result, no duplicate created.
        send_admin_error(handler, 409, f"Path {norm!r} is already excluded.")
        return
    add_excluded_path(norm)
    write_admin_config()
    _broadcast_exclusion_change("added", "path", norm)
    send_admin_ok(handler, {"added": norm, "excluded_paths": sorted(EXCLUDED_PATHS)})
    print(f"[Admin] Excluded path added: {norm}")


def handle_admin_exclusion_path_remove(handler, body: dict) -> None:
    norm = normalize_path(body.get("path", ""))
    if not norm:
        send_admin_error(handler, 400, "Field 'path' is required.")
        return
    if norm not in EXCLUDED_PATHS:
        send_admin_error(handler, 404, f"Path {norm!r} is not excluded.")
        return
    remove_excluded_path(norm)
    write_admin_config()
    _broadcast_exclusion_change("removed", "path", norm)
    send_admin_ok(handler, {"removed": norm, "excluded_paths": sorted(EXCLUDED_PATHS)})
    print(f"[Admin] Excluded path removed: {norm}")


def handle_admin_exclusion_extension_add(handler, body: dict) -> None:
    norm = normalize_extension(body.get("extension", ""))
    if not norm:
        send_admin_error(handler, 400, "Field 'extension' is required.")
        return
    if norm in EXCLUDED_EXTENSIONS:
        send_admin_error(handler, 409, f"Extension {norm!r} is already excluded.")
        return
    add_excluded_extension(norm)
    write_admin_config()
    _broadcast_exclusion_change("added", "extension", norm)
    send_admin_ok(handler, {"added": norm, "excluded_extensions": sorted(EXCLUDED_EXTENSIONS)})
    print(f"[Admin] Excluded extension added: {norm}")


def handle_admin_exclusion_extension_remove(handler, body: dict) -> None:
    norm = normalize_extension(body.get("extension", ""))
    if not norm:
        send_admin_error(handler, 400, "Field 'extension' is required.")
        return
    if norm not in EXCLUDED_EXTENSIONS:
        send_admin_error(handler, 404, f"Extension {norm!r} is not excluded.")
        return
    if is_default_extension(norm):
        send_admin_error(handler, 400, f"Extension {norm!r} is a config-defined default and cannot be removed.")
        return
    remove_excluded_extension(norm)
    write_admin_config()
    _broadcast_exclusion_change("removed", "extension", norm)
    send_admin_ok(handler, {"removed": norm, "excluded_extensions": sorted(EXCLUDED_EXTENSIONS)})
    print(f"[Admin] Excluded extension removed: {norm}")


def handle_admin_get_config(handler) -> None:
    send_admin_ok(handler, {
        "networks": [str(n) for n in ALLOWED_NETWORKS],
        "banned":   sorted(BANNED_IPS),
        "notes":    admin_notes,
        "strict_mode": get_strict_mode(),
        # Kill switch is active when the allowlist is empty (lockdown).
        "lockdown": len(ALLOWED_NETWORKS) == 0,
        "excluded_paths": sorted(EXCLUDED_PATHS),
        "excluded_extensions": sorted(EXCLUDED_EXTENSIONS),
    })


# Strict Mode handlers

def handle_strict_mode_toggle(handler, body: dict) -> None:
    value = bool(body.get("enabled", False))
    current = set_strict_mode(value)
    # Persist the new state so it survives server restarts.
    write_admin_config()

    _sse_broadcast = _g.get("sse_broadcast")
    if _sse_broadcast:
        _sse_broadcast("strict_mode_change", {"enabled": current})

    print(f"[Admin] Strict Mode {'ENABLED' if current else 'DISABLED'}")
    send_admin_ok(handler, {"strict_mode": current})


def handle_strict_queue_get(handler) -> None:
    items = get_strict_queue_snapshot()
    send_admin_ok(handler, {"queue": items, "count": len(items)})


def handle_strict_approve(handler, body: dict) -> None:
    uid = body.get("id", "").strip()
    if not uid:
        send_admin_error(handler, 400, "id is required.")
        return

    entry = get_strict_entry(uid)

    if not entry:
        send_admin_error(handler, 404, f"No pending upload with id {uid!r}")
        return

    # Signal the blocked request thread to proceed
    entry["approved"].set()
    send_admin_ok(handler, {"approved": uid, "filename": entry["filename"]})
    print(f"[Strict] Approved upload: {entry['filename']} from {entry['uploader_ip']}")


def handle_strict_reject(handler, body: dict) -> None:
    uid = body.get("id", "").strip()
    if not uid:
        send_admin_error(handler, 400, "id is required.")
        return

    entry = get_strict_entry(uid)

    if not entry:
        send_admin_error(handler, 404, f"No pending upload with id {uid!r}")
        return

    entry["rejected"].set()
    entry["approved"].set()   # wake the blocked thread so it can check rejected.is_set()
    send_admin_ok(handler, {"rejected": uid, "filename": entry["filename"]})
    print(f"[Strict] Rejected upload: {entry['filename']} from {entry['uploader_ip']}")

def handle_strict_preview(handler, body_or_query) -> None:
    """Stream the RAM-buffered file to the admin for preview/download.
    Accepts either a JSON body dict or a parse_qs query_params dict."""
    uid = ""
    if isinstance(body_or_query, dict):
        # parse_qs returns lists; JSON body returns scalars
        val = body_or_query.get("id", "")
        uid = (val[0] if isinstance(val, list) else val).strip()

    if not uid:
        send_admin_error(handler, 400, "id is required.")
        return

    entry = get_strict_entry(uid)

    if not entry:
        send_admin_error(handler, 404, f"No pending upload with id {uid!r}")
        return

    buf = entry.get("buffer")
    if buf is None:
        send_admin_error(handler, 400, "File is too large to preview from RAM.")
        return

    buf.seek(0)
    data = buf.read()
    ctype = entry.get("content_type") or "application/octet-stream"
    fname = entry.get("filename", "preview")

    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Content-Disposition", f'attachment; filename="{fname}"')
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


# single entry point called from server.py

def handle_admin_request(handler, parsed_url, query_params) -> None:
    """
    Called from ModernHandler.do_GET / do_POST after is_localhost() has
    already been confirmed. Routes to the appropriate sub-handler.
    """
    path   = parsed_url.path
    method = handler.command  # 'GET' or 'POST'

    # ── Login (no auth cookie required) 
    if path == "/admin/login":
        if method == "GET":
            handle_admin_login_get(handler)
        elif method == "POST":
            handle_admin_login_post(handler)
        else:
            send_admin_error(handler, 405, "Method not allowed.")
        return

    # ── Serve admin dashboard HTML 
    if path == "/admin" and method == "GET":
        if not check_admin_session_only(handler):
            _redirect_to_login(handler)
            return
        _serve_admin_html(handler)
        return

    # ── Preview in new tab: session cookie only (no CSRF header in new tabs) 
    if path == "/admin/strict/preview" and method == "GET":
        if not check_admin_session_only(handler):
            send_admin_error(handler, 401, "Unauthorized. Invalid or missing admin session.")
            return
        handle_strict_preview(handler, query_params)
        return

    # ── All other endpoints require full auth (session + CSRF) 
    if not check_admin_auth(handler):
        send_admin_error(handler, 401, "Unauthorized. Invalid or missing admin credentials.")
        return

    # ── GET endpoints 
    if method == "GET":
        if path == "/admin/radar":         handle_admin_radar(handler);          return
        if path == "/admin/storage":       handle_admin_storage(handler);        return
        if path == "/admin/ratelimit":     handle_admin_ratelimit_status(handler); return
        if path == "/admin/upload/locks":  handle_admin_upload_locks(handler);   return
        if path == "/admin/config":        handle_admin_get_config(handler);     return
        if path == "/admin/exclusions":    handle_admin_exclusions_get(handler); return
        if path == "/admin/strict/queue":  handle_strict_queue_get(handler);     return
        if path == "/admin/strict/status":
            send_admin_ok(handler, {"strict_mode": get_strict_mode()});          return
        if path == "/admin/strict/preview":
            handle_strict_preview(handler, query_params);                         return
        send_admin_error(handler, 404, f"Unknown admin endpoint: GET {path}")
        return

    # ── POST endpoints 
    if method == "POST":
        content_length = int(handler.headers.get("Content-Length", 0))
        if content_length > 65_536:   # 64 KB cap
            send_admin_error(handler, 413, "Admin payload too large.")
            return
        try:
            raw_body = handler.rfile.read(content_length) if content_length else b"{}"
            body = json.loads(raw_body or b"{}")
        except json.JSONDecodeError:
            send_admin_error(handler, 400, "Request body must be valid JSON.")
            return

        if path == "/admin/network/add":          handle_admin_network_add(handler, body);          return
        if path == "/admin/network/remove":       handle_admin_network_remove(handler, body);       return
        if path == "/admin/exclusions/path/add":       handle_admin_exclusion_path_add(handler, body);       return
        if path == "/admin/exclusions/path/remove":    handle_admin_exclusion_path_remove(handler, body);    return
        if path == "/admin/exclusions/extension/add":     handle_admin_exclusion_extension_add(handler, body);     return
        if path == "/admin/exclusions/extension/remove":  handle_admin_exclusion_extension_remove(handler, body);  return
        if path == "/admin/killswitch":           handle_admin_killswitch(handler, body);           return
        if path == "/admin/killswitch/off":       handle_admin_killswitch_off(handler, body);       return
        if path == "/admin/ban":                  handle_admin_ban(handler, body);                  return
        if path == "/admin/unban":                handle_admin_unban(handler, body);                return
        if path == "/admin/upload/cancel":        handle_admin_upload_cancel(handler, body);        return
        if path == "/admin/upload/cooldown":      handle_admin_upload_cooldown(handler, body);      return        
        if path == "/admin/clipboard/wipe":       handle_admin_clipboard_wipe(handler, body);       return
        if path == "/admin/ratelimit/reset":      handle_admin_ratelimit_reset(handler, body);      return
        if path == "/admin/strictmode":           handle_strict_mode_toggle(handler, body);         return
        if path == "/admin/strict/approve":       handle_strict_approve(handler, body);             return
        if path == "/admin/strict/reject":        handle_strict_reject(handler, body);              return
        if path == "/admin/strict/preview":       handle_strict_preview(handler, body);             return
        send_admin_error(handler, 404, f"Unknown admin endpoint: POST {path}")
        return

    send_admin_error(handler, 405, "Method not allowed.")
