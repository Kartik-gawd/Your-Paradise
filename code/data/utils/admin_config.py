import datetime
import ipaddress
import json
import os
import threading

from utils.strict_mode import get_strict_mode, set_strict_mode

admin_config_lock = threading.Lock()

ALLOWED_NETWORKS: list = []
BANNED_IPS: set        = set()
admin_notes: dict     = {}

# Snapshot of the allowlist taken when the kill switch is activated, so the
# subnets can be restored later. Persisted in admin_config.json.
previous_networks: list = []

# Admin-managed exclusion system: explicit paths + extensions.
# EXCLUDED_EXTENSIONS is persisted in admin_config.json so that administrator-defined
# changes (both additions and removals of default extensions) remain effective across
# server restarts. If no configuration exists, default exclusions are loaded.
EXCLUDED_PATHS: set      = set()
EXCLUDED_EXTENSIONS: set = set()
_BASE_EXCLUDED_EXTENSIONS: set = set()

# Remember where the config file lives so write_admin_config() can be called
# without an argument from the admin handlers.
_CONFIG_PATH: str = ""

def _config_path(base_file: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(base_file)), "admin_config.json")

def normalize_extension(ext: str) -> str:
    """Lowercase, dot-prefixed, whitespace-stripped extension. Returns '' if empty."""
    ext = (ext or "").strip().lower()
    if not ext:
        return ""
    if not ext.startswith("."):
        ext = "." + ext
    return ext

def normalize_path(path: str) -> str:
    """Normalize a user-supplied exclusion path so equivalent forms collapse
    to one representation (slashes, case of separators, trailing/leading slashes)."""
    path = (path or "").strip().replace("\\", "/").strip("/")
    if not path:
        return ""
    return os.path.normpath(path).replace("\\", "/")

def load_admin_config(base_file: str, admin_password: str, base_excluded_extensions=None) -> bytes:
    """
    Populates ALLOWED_NETWORKS, BANNED_IPS, admin_notes, EXCLUDED_PATHS,
    EXCLUDED_EXTENSIONS (effective = base_excluded_extensions ∪ admin-added).
    Returns the SHA-256 hash of admin_password for the caller to store.
    """
    global ALLOWED_NETWORKS, BANNED_IPS, admin_notes, previous_networks, _CONFIG_PATH
    global EXCLUDED_PATHS, EXCLUDED_EXTENSIONS, _BASE_EXCLUDED_EXTENSIONS
    import hashlib
    password_hash = hashlib.sha256(admin_password.encode()).digest()

    _BASE_EXCLUDED_EXTENSIONS = {normalize_extension(e) for e in (base_excluded_extensions or set()) if normalize_extension(e)}

    _CONFIG_PATH = _config_path(base_file)
    cfg_path = _CONFIG_PATH
    if not os.path.exists(cfg_path):
        # Mutate in place (not reassign) so modules that did
        # `from utils.admin_config import *` keep pointing at the same objects.
        ALLOWED_NETWORKS.clear()
        ALLOWED_NETWORKS.extend([
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
        ])
        BANNED_IPS.clear()
        admin_notes.clear()
        EXCLUDED_PATHS.clear()
        EXCLUDED_EXTENSIONS.clear()
        EXCLUDED_EXTENSIONS.update(_BASE_EXCLUDED_EXTENSIONS)
        write_admin_config(base_file)
        return password_hash

    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        ALLOWED_NETWORKS.clear()
        for net_str in cfg.get("allowed_networks", []):
            try:
                ALLOWED_NETWORKS.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError:
                print(f"[Admin] Warning: invalid network in config: {net_str!r}")
        BANNED_IPS.clear()
        BANNED_IPS.update(cfg.get("banned_ips", []))
        admin_notes.clear()
        admin_notes.update(cfg.get("notes", {}))
        previous_networks.clear()
        for net_str in cfg.get("previous_networks", []):
            try:
                previous_networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError:
                print(f"[Admin] Warning: invalid previous network in config: {net_str!r}")
        # Load administrator-defined exclusions (or defaults if not present)
        EXCLUDED_PATHS.clear()
        if "excluded_paths" in cfg and cfg.get("excluded_paths") is not None:
            EXCLUDED_PATHS.update(p for p in (normalize_path(x) for x in cfg.get("excluded_paths", [])) if p)

        EXCLUDED_EXTENSIONS.clear()
        if "excluded_extensions" in cfg and cfg.get("excluded_extensions") is not None:
            EXCLUDED_EXTENSIONS.update(e for e in (normalize_extension(x) for x in cfg.get("excluded_extensions", [])) if e)
        else:
            EXCLUDED_EXTENSIONS.update(_BASE_EXCLUDED_EXTENSIONS)
        # Restore the persisted strict-mode state.
        set_strict_mode(bool(cfg.get("strict_mode", False)))
        print(f"[Admin] Config loaded: {len(ALLOWED_NETWORKS)} networks, "
              f"{len(BANNED_IPS)} banned IPs, "
              f"{len(EXCLUDED_PATHS)} excluded paths, "
              f"{len(EXCLUDED_EXTENSIONS)} excluded extensions, "
              f"strict_mode={get_strict_mode()}.")
    except Exception as e:
        print(f"[Admin] Config load error: {e} — using defaults.")
        EXCLUDED_EXTENSIONS.clear()
        EXCLUDED_EXTENSIONS.update(_BASE_EXCLUDED_EXTENSIONS)

    return password_hash

def _invalidate_listing_cache() -> None:
    """Clear cached directory listings so exclusion changes take effect
    immediately, without a server restart. Imported lazily to avoid a
    circular import (dir_cache does not depend on admin_config)."""
    try:
        from utils.dir_cache import _invalidate_dir_cache
        _invalidate_dir_cache()
    except Exception as e:
        print(f"[Admin] Warning: could not invalidate dir cache: {e}")

def add_excluded_path(path: str) -> str:
    norm = normalize_path(path)
    if norm:
        EXCLUDED_PATHS.add(norm)
        _invalidate_listing_cache()
    return norm

def remove_excluded_path(path: str) -> str:
    norm = normalize_path(path)
    EXCLUDED_PATHS.discard(norm)
    _invalidate_listing_cache()
    return norm

def add_excluded_extension(ext: str) -> str:
    norm = normalize_extension(ext)
    if norm:
        EXCLUDED_EXTENSIONS.add(norm)
        _invalidate_listing_cache()
    return norm

def remove_excluded_extension(ext: str) -> str:
    """Removes an excluded extension and invalidates listing cache."""
    norm = normalize_extension(ext)
    if norm:
        EXCLUDED_EXTENSIONS.discard(norm)
        _invalidate_listing_cache()
    return norm

def is_default_extension(ext: str) -> bool:
    """True if ext is one of config.py's static default extensions."""
    return normalize_extension(ext) in _BASE_EXCLUDED_EXTENSIONS

def write_admin_config(base_file: str = "") -> None:
    with admin_config_lock:
        cfg = {
            "version": 1,
            "last_modified": datetime.datetime.utcnow().isoformat() + "Z",
            "allowed_networks": [str(n) for n in ALLOWED_NETWORKS],
            "banned_ips": sorted(BANNED_IPS),
            "notes": admin_notes,
            "strict_mode": get_strict_mode(),
            "previous_networks": [str(n) for n in previous_networks],
            "excluded_paths": sorted(EXCLUDED_PATHS),
            "excluded_extensions": sorted(EXCLUDED_EXTENSIONS),
        }
        # If no base_file was supplied, fall back to the path recorded by
        # load_admin_config(). This lets admin handlers call
        # write_admin_config() with no arguments.
        cfg_path = _config_path(base_file) if base_file else _CONFIG_PATH
        if not cfg_path:
            raise RuntimeError("write_admin_config() called before load_admin_config()")
        tmp_path = cfg_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            os.replace(tmp_path, cfg_path)
        except Exception as e:
            print(f"[Admin] Config write error: {e}")
            raise
