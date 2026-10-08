import http.server
import socketserver
import os
import urllib.parse
import html
import sys
import io
import queue
import datetime
import socket
import re
import ipaddress
import threading
import time
import ssl                       
import functools
import json
import zipfile
import secrets
import subprocess
from collections import defaultdict

# utility imports
from utils.rate_limit import *
from utils.sse import sse_broadcast, sse_send_to, _sse_clients, _sse_clients_lock
from utils.presence import *
from utils.dir_cache import _cached_listdir, _invalidate_dir_cache
from utils.admin_config import (
    EXCLUDED_EXTENSIONS as ADMIN_EXCLUDED_EXTENSIONS,
    EXCLUDED_PATHS as ADMIN_EXCLUDED_PATHS,
    normalize_path,
)
from utils.media import *
from utils.sweeper import *
from utils.network import *
from utils.permissions import *

from config import *
import admin_core
import peer

try:
    import segno
except ImportError:
    segno = None

SECRET_TOKEN = secrets.token_urlsafe(16)

try:
    from zeroconf import Zeroconf, ServiceInfo
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False
    print("LAN discovery disabled."
          "Run:  pip install zeroconf")

def _get_permissions(ip: str, is_host: bool) -> dict:
    return get_permissions(ip, is_host)

# Secure session cookie
SESSION_SECRET = secrets.token_urlsafe(32)

#  Semaphore that caps concurrent zip-download threads
zip_semaphore = threading.Semaphore(MAX_CONCURRENT_ZIPS)

clipboard_messages = []
clipboard_lock     = threading.Lock()

def _get_bundled_assets_dir():
    if getattr(sys, 'frozen', False):
        return os.path.join(getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(sys.executable))), "data")
    return os.path.dirname(os.path.abspath(__file__))

TEMPLATE_PATH = os.path.join(_get_bundled_assets_dir(), "index.html")

def _get_app_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

SUBTITLES_EXTRACT_DIR = os.path.join(_get_app_base_dir(), "subtitles extracted")
os.makedirs(SUBTITLES_EXTRACT_DIR, exist_ok=True)

# Subtitle extraction queue 
_extraction_lock   = threading.Lock()
_extraction_queue  = queue.Queue()
_queued_video_keys = set()
_active_extraction = {"video_key": None, "cancel_event": None, "process": None}


def _cached_subtitle_urls(filepath, extract_dir):
    # directory listing
    video_stem = os.path.splitext(os.path.basename(filepath))[0]
    sub_dir    = os.path.join(extract_dir, video_stem)
    if not os.path.isdir(sub_dir):
        return []
    urls = []
    try:
        for fname in os.listdir(sub_dir):
            if fname.lower().endswith(('.vtt', '.srt')):
                rel = os.path.relpath(os.path.join(sub_dir, fname), extract_dir).replace('\\', '/')
                urls.append('/__subtitles_extracted__/' + rel)
    except OSError:
        pass
    return urls


def _cancel_video_extraction(video_key):
    
    with _extraction_lock:
        if _active_extraction.get("video_key") == video_key:
            cancel_event = _active_extraction.get("cancel_event")
            if cancel_event:
                cancel_event.set()
            proc = _active_extraction.get("process")
            if proc is not None and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        _queued_video_keys.discard(video_key)


def _enqueue_subtitle_extraction(video_key, filepath, base, sse_uuid):
    with _extraction_lock:
        if _active_extraction.get("video_key") == video_key:
            return
        if video_key in _queued_video_keys:
            return
        _queued_video_keys.add(video_key)
    _extraction_queue.put((video_key, filepath, base, sse_uuid))


def _extraction_worker():
    while True:
        video_key, filepath, base, sse_uuid = _extraction_queue.get()
        with _extraction_lock:
            _queued_video_keys.discard(video_key)
            cancel_event = threading.Event()
            _active_extraction["video_key"]    = video_key
            _active_extraction["cancel_event"] = cancel_event
            _active_extraction["process"]      = None

        def _register_process(proc, _key=video_key):
            with _extraction_lock:
                if _active_extraction.get("video_key") == _key:
                    _active_extraction["process"] = proc

        def _on_ready(sub_url, _key=video_key):
            if sse_uuid:
                sse_send_to(sse_uuid, "subtitle_ready", {"video": _key, "sub_url": sub_url})

        try:
            
            _saved_stderr_fd = None
            _null_stderr_fd  = None
            try:
                _null_stderr_fd  = os.open(os.devnull, os.O_WRONLY)
                _saved_stderr_fd = os.dup(2)
                os.dup2(_null_stderr_fd, 2)
            except Exception:
                # Fall back to normal stderr if the OS-level redirect fails.
                if _null_stderr_fd is not None:
                    try:
                        os.close(_null_stderr_fd)
                    except Exception:
                        pass
                _null_stderr_fd  = None
                _saved_stderr_fd = None

            try:
                extract_subtitles(
                    filepath, base, SUBTITLES_EXTRACT_DIR,
                    cancel_event=cancel_event,
                    on_ready=_on_ready,
                    register_process=_register_process,
                )
            finally:
                if _saved_stderr_fd is not None:
                    try:
                        os.dup2(_saved_stderr_fd, 2)
                    except Exception:
                        pass
                    try:
                        os.close(_saved_stderr_fd)
                    except Exception:
                        pass
                if _null_stderr_fd is not None:
                    try:
                        os.close(_null_stderr_fd)
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Subtitle queue] extraction error: {e}")
        finally:
            was_cancelled = cancel_event.is_set()
            if sse_uuid:
                sse_send_to(sse_uuid, "subtitle_extraction_done", {"video": video_key, "cancelled": was_cancelled})
            with _extraction_lock:
                if _active_extraction.get("video_key") == video_key:
                    _active_extraction["video_key"]    = None
                    _active_extraction["cancel_event"] = None
                    _active_extraction["process"]      = None
        _extraction_queue.task_done()


threading.Thread(target=_extraction_worker, daemon=True).start()


APP_DIR = _get_bundled_assets_dir()

# First path segment(s) that identify the app's own static assets.
_APP_STATIC_PREFIXES = ('style.css', 'icon', 'effects')


def _is_admin_excluded(fullname: str, name: str) -> bool:
  
    if not os.path.isdir(fullname):
        ext = os.path.splitext(name)[1].lower()
        if ext in ADMIN_EXCLUDED_EXTENSIONS:
            return True
    try:
        rel = normalize_path(os.path.relpath(fullname, os.getcwd()))
    except ValueError:
        return False
    if not rel:
        return False
    if rel in ADMIN_EXCLUDED_PATHS:
        return True
    return any(rel == p or rel.startswith(p + "/") for p in ADMIN_EXCLUDED_PATHS)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads      = True
    allow_reuse_address = True
    # override server_bind to tune the socket before the OS assigns the port, which is the only safe window to change buffer options.
    def server_bind(self):
        s = self.socket
 
        # Disable Nagle's algorithm → small packets are sent immediately instead of being coalesced. 
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
 
        super().server_bind()

class ModernHandler(http.server.SimpleHTTPRequestHandler):

    def handle(self):
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass  # Client closed the connection, perfectly normal.

    def update_active_user(self, ip):
        with active_users_lock:
            active_users[ip] = time.time()

    def has_write_access(self):
        ip = self.client_address[0]
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return True
        except Exception:
            pass

        for part in self.headers.get('Cookie', '').split(';'):
            part = part.strip()
            if part.startswith('session='):
                value = part[len('session='):]
                if secrets.compare_digest(value, SESSION_SECRET):
                    return True
        return False

    def is_admin(self):
    
        ip = self.client_address[0]
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return True
        except Exception:
            pass
        if ip == get_local_ip():
            return True
        return False

    def check_access(self) -> bool:
        return admin_core.check_access(self)

    def log_error(self, format, *args):
        if args and args[0] in (429, 403):
            return
        super().log_error(format, *args)

    def log_message(self, format, *args):
        # Safely get path and command (prevents AttributeError on malformed requests)
        path = getattr(self, 'path', '')
        command = getattr(self, 'command', '')

        # Suppress console msg:
        if '/clipboard' in path and command in ('GET', 'POST'):
            return

        # Suppress alias and events polling noise
        if command == 'POST' and urllib.parse.urlparse(path).path == '/alias':
            return
        if command == 'GET' and urllib.parse.urlparse(path).path == '/events':
            return

        # Suppress subtitle-extraction noise (served .vtt files and cancel requests).
        _SUBTITLE_POLL_PATHS = (
            '/__subtitles_extracted__/', '/cancel_extraction',
        )
        if command == 'GET' and path.startswith(_SUBTITLE_POLL_PATHS):
            return
        if command == 'GET' and urllib.parse.urlparse(path).path in _SUBTITLE_POLL_PATHS:
            return
        
        _ADMIN_POLL_PATHS = {
            '/admin/radar', '/admin/storage', '/admin/ratelimit',
            '/admin/upload/locks', '/admin/config', '/admin/strict/queue',
            '/admin/strict/status',
        }
        if command == 'GET' and urllib.parse.urlparse(path).path in _ADMIN_POLL_PATHS:
            return

        _P2P_POLL_PATHS = {'/p2p/register', '/p2p/peers', '/p2p/heartbeat', '/p2p/signal','/p2p/disconnect'}
        if urllib.parse.urlparse(path).path in _P2P_POLL_PATHS:
            return
        
        parsed = urllib.parse.urlparse(path)
        qp     = urllib.parse.parse_qs(parsed.query)
        
        if qp.get('filename') and qp.get('chunk'):
            if qp.get('chunk')[0] != '0':
                return
                
        if hasattr(self, 'headers') and self.headers and self.headers.get('Range'):
            return

        sys.stderr.write("%s - - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args,
        ))


    def translate_path(self, path):
        #Resolve app assets (style.css, /icon/*, /effects/*) from APP_DIR.

        # Normalize: strip query string, URL-decode, replace backslashes.
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = urllib.parse.unquote(path).replace('\\', '/')

        # Make it absolute and POSIX-style so we can inspect the leading segment.
        if not path.startswith('/'):
            path = '/' + path
        first = path.lstrip('/').split('/', 1)[0].lower()

        if first in _APP_STATIC_PREFIXES:
            relative = path.lstrip('/')
            full = os.path.normpath(os.path.join(APP_DIR, relative.replace('/', os.sep)))
            # Security: prevent escaping APP_DIR.
            if not (full == APP_DIR or full.startswith(APP_DIR + os.sep)):
                return os.path.join(os.getcwd(), 'nonexistent')
            return full

        # Everything else falls through to the default (served-folder) behavior.
        return super().translate_path(path)

    # Request routing 

    def send_head(self):
        parsed_url = urllib.parse.urlparse(self.path)
       
        if parsed_url.path == '/clipboard':
            now = time.time()
            with active_users_lock:
                active_ips = [ip for ip, t in active_users.items() if now - t < 15]

            resp_data = {'messages': list(clipboard_messages), 'online_count': len(active_ips)}
            if self.has_write_access():
                resp_data['active_ips'] = active_ips

            self.send_response(200)
            self.send_header("Content-type", "application/json; charset=utf-8")
            self.end_headers()
            with clipboard_lock:
                return io.BytesIO(json.dumps(resp_data).encode('utf-8'))

        query_params = urllib.parse.parse_qs(parsed_url.query)
        if 'action' in query_params and query_params['action'][0] == 'zip':
            self.handle_zip_download(parsed_url.path)
            return None

        path = self.translate_path(parsed_url.path)
        if os.path.isdir(path):
            if not parsed_url.path.endswith('/'):
                self.send_response(301)
                self.send_header("Location", parsed_url.path + "/")
                self.end_headers()
                return None
            
            return self.list_directory(path)
        ctype = self.guess_type(path)
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(404, "File not found")
            return None
        
        if "Range" in self.headers:
            self.handle_range_request(f, path, ctype)
            return None

        try:
            fs = os.fstat(f.fileno())
            self.send_response(200)
            self.send_header("Content-type",   ctype)
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified",  self.date_time_string(fs.st_mtime))
            self.send_header("Accept-Ranges",  "bytes")
            
            # Force a real file-save dialog when the client requests a download
            query_params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if query_params.get('action', [None])[0] == 'download':
                safe_name = os.path.basename(path)
                self.send_header("Content-Disposition",
                                f"attachment; filename*=UTF-8''{urllib.parse.quote(safe_name)}")

            CACHEABLE_TYPES = (
                 "image/", "video/", "audio/",
                 "text/css", "application/javascript",
                 "font/",
             )
            if any(ctype.startswith(t) for t in CACHEABLE_TYPES):
                 self.send_header("Cache-Control", "public, max-age=3600")
            else:
                 self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return f

        except Exception:
            f.close()
            raise


    def handle_zip_download(self, path):
        target_path = self.translate_path(path)
        
        if not os.path.exists(target_path):
            self.send_error(404, "File or Directory not found")
            return

        if not zip_semaphore.acquire(blocking=False):
            self.send_error(
                503,
                f"Server is already streaming {MAX_CONCURRENT_ZIPS} zip archives. "
                "Please try again in a moment.",
            )
            return

        try:
            base_name = os.path.basename(os.path.normpath(target_path)) or "download"
            download_name = f"{base_name}.zip"

            self.send_response(200)
            self.send_header('Content-type', 'application/zip')
            self.send_header('Content-Disposition', f"attachment; filename*=UTF-8''{urllib.parse.quote(download_name)}")
            self.end_headers()

            try:
                with zipfile.ZipFile(self.wfile, 'w', zipfile.ZIP_STORED, allowZip64=True) as zf:
                    # Walk and preserve relative paths.
                    for root, dirs, files in os.walk(target_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            zf.write(file_path, os.path.relpath(file_path, target_path))

            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                pass
            except Exception as e:
                print(f"Zip Streaming Error: {e}")
        finally:
            zip_semaphore.release()

    def handle_range_request(self, f, path, ctype):
        try:
            file_size   = os.path.getsize(path)
            range_match = re.search(r'bytes=(\d+)-(\d*)', self.headers['Range'])
            if range_match:
                first_byte = int(range_match.group(1))
                last_byte  = int(range_match.group(2)) if range_match.group(2) else file_size - 1
                length     = last_byte - first_byte + 1
                self.send_response(206)
                self.send_header('Content-type',   ctype)
                self.send_header('Content-Range',  f'bytes {first_byte}-{last_byte}/{file_size}')
                self.send_header('Content-Length', str(length))
                self.send_header('Accept-Ranges',  'bytes')
                self.end_headers()
                f.seek(first_byte)
                self.copyfile(f, self.wfile, length)
            else:
                self.send_error(400, "Bad Range Header")

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            print(f"Range Error: {e}")
        finally:
            f.close()

    def copyfile(self, source, outputfile, length=None):
        BUFFER_SIZE = 65536
        try:
            if length is None:
                while True:
                    data = source.read(BUFFER_SIZE)
                    if not data:
                        break
                    outputfile.write(data)
            else:
                remaining = length
                while remaining > 0:
                    data = source.read(min(BUFFER_SIZE, remaining))
                    if not data:
                        break
                    outputfile.write(data)
                    remaining -= len(data)
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            print(f"Copyfile Error: {e}")

    def _build_presence_payload(self, for_client_ip: str = None) -> dict:

        # if socket is open, client is there
        with _sse_clients_lock:
            online_ips = list({entry["ip"] for entry in _sse_clients.values()})
        with user_aliases_lock:
            aliases = {ip: user_aliases.get(ip, ip) for ip in online_ips}

        local_ips = ["127.0.0.1", "::1", get_local_ip()]

        payload = {
            "online_ips": online_ips,
            "online_count": len(online_ips),
            "aliases":       aliases,
            "server_ips":   local_ips,
        }
        if for_client_ip:
            payload["your_ip"] = for_client_ip
        return payload

    def _probe_video(self, filepath):
        return probe_video(filepath)

    def _cached_subs(self, filepath):
        return _cached_subtitle_urls(filepath, SUBTITLES_EXTRACT_DIR)

    def _serve_extracted_subtitle(self, url_path):
        rel = urllib.parse.unquote(url_path[len('/__subtitles_extracted__/'):]).replace('\\', '/').lstrip('/')
        if '..' in rel.split('/'):
            self.send_error(403, "Forbidden")
            return
        file_path = os.path.join(SUBTITLES_EXTRACT_DIR, *rel.split('/'))
        if not os.path.isfile(file_path):
            self.send_error(404, "Not Found")
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except OSError:
            self.send_error(500, "Internal Server Error")
            return
        self.send_response(200)
        self.send_header('Content-type', 'text/vtt' if file_path.lower().endswith('.vtt') else 'application/octet-stream')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_video_meta(self, parsed_url, query_params):
       
        file_path = self.translate_path(parsed_url.path.replace('/video_meta', '', 1))
        # Accept ?file=<url-encoded-path> as alternative
        fp_param = query_params.get('file', [None])[0]
        if fp_param:
            file_path = self.translate_path(fp_param)
        if not os.path.isfile(file_path):
            self.send_error(404, "File not found")
            return
        base, _ = os.path.splitext(file_path)
   
        video_key = fp_param or parsed_url.path
        sse_uuid  = query_params.get('sse_uuid', [None])[0]

        cached_subs = self._cached_subs(file_path)
        meta = self._probe_video(file_path)
        meta["extracted_subs"] = cached_subs

        total_sub_streams = len(meta.get("subtitle_tracks", []))
        if total_sub_streams > 0:
          
            _enqueue_subtitle_extraction(video_key, file_path, base, sse_uuid)
            meta["extraction_pending"] = True
        else:
            meta["extraction_pending"] = False

        body = json.dumps(meta).encode()
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_sse_stream(self):
        ip        = self.client_address[0]
        # Assign a UUID per browser tab so peers behind the same NAT are distinct.
        sse_uuid  = secrets.token_urlsafe(16)

        # client side msg queue
        client_queue = queue.Queue(maxsize=100)

        with _sse_clients_lock:
            _sse_clients[sse_uuid] = {"queue": client_queue, "ip": ip}

        with active_users_lock:
            active_users[ip] = time.time()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        with clipboard_lock:
            initial_msgs = list(clipboard_messages)
        initial_frame = (
            f"event: init\n"
            f"data: {json.dumps({'messages': initial_msgs, 'your_ip': ip, 'sse_uuid': sse_uuid})}\n\n"
        ).encode("utf-8")
        self.wfile.write(initial_frame)
        self.wfile.flush()

        sse_send_to(sse_uuid, "presence_update", self._build_presence_payload(for_client_ip=ip))
        # Broadcast the new connection
        sse_broadcast("presence_update", self._build_presence_payload(), exclude_id=sse_uuid)

        # Main sse loop
        try:
            while True:
                try:
                    # Block either 1) msg arrives 2) after 20s
                    frame = client_queue.get(timeout=20)
                    self.wfile.write(frame)
                    self.wfile.flush()
                except queue.Empty:
                    # Keep alive to avoid 504 timeout
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _sse_clients_lock:
                _sse_clients.pop(sse_uuid, None)
            with active_users_lock:
                active_users.pop(ip, None)
            # Purge any p2p peer registered to this specific tab UUID
            peer.purge_by_sse_uuid(sse_uuid)
            # Broadcast who left
            sse_broadcast("presence_update", self._build_presence_payload())

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
 
        # Admin panel: localhost / host admin only
        if parsed_url.path.startswith('/admin'):
            if not (admin_core.is_localhost(self) or self.is_admin()):
                self.send_error(404, "Not Found")
                return
            query_params = urllib.parse.parse_qs(parsed_url.query)
            admin_core.handle_admin_request(self, parsed_url, query_params)
            return
 
        #reject known-banned IPs 
        if self.client_address[0] in admin_core.BANNED_IPS:
            self.send_error(403, "Forbidden: You have been BANNED by the admin")
            return
 
        api_endpoints = ['/events', '/clipboard', '/alias']
        if parsed_url.path in api_endpoints:
            if not admin_core.is_localhost(self) and not rate_limiter.is_allowed(self.client_address[0]):
                self.send_error(429, "Too Many Requests, please slow down")
                return

        if not self.check_access():
            self.send_error(403, "Forbidden")
            return

        query_params = urllib.parse.parse_qs(parsed_url.query)

        if 'auth' in query_params:
            if query_params['auth'][0] == SECRET_TOKEN:
                # store SESSION_SECRET
                self.send_response(303)
                self.send_header(
                    "Set-Cookie",
                    f"session={SESSION_SECRET}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Strict",
                )
                self.send_header("Location", parsed_url.path)
                self.end_headers()
            else:
                self.send_error(403, "Invalid auth token")
            return

        if parsed_url.path == '/events':
            self.handle_sse_stream()        # blocks until client disconnects
            return

        if parsed_url.path == '/video_meta':
            self._handle_video_meta(parsed_url, query_params)
            return

        if parsed_url.path == '/cancel_extraction':
            video_key = query_params.get('video', [None])[0]
            if video_key:
                _cancel_video_extraction(video_key)
            self.send_response(204)
            self.end_headers()
            return

        # cached subtitle used by Legacy mode
        if parsed_url.path == '/cached_subs':
            fp_param = query_params.get('file', [None])[0]
            file_path = self.translate_path(fp_param) if fp_param else None
            cached = self._cached_subs(file_path) if file_path and os.path.isfile(file_path) else []
            body = json.dumps({"extracted_subs": cached}).encode()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # peer.html routes 
        if parsed_url.path == '/peer.html' or parsed_url.path.startswith('/p2p/'):
            if peer.handle_request(self):
                return
 
        if parsed_url.path.startswith('/__subtitles_extracted__/'):
            self._serve_extracted_subtitle(parsed_url.path)
            return

        super().do_GET()

    def do_POST(self):
        parsed_url   = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
 
        # Admin panel: localhost / host admin only, bypass all other checks 
        if parsed_url.path.startswith('/admin'):
            if not (admin_core.is_localhost(self) or self.is_admin()):
                self.send_error(404, "Not Found")
                return
            admin_core.handle_admin_request(self, parsed_url, query_params)
            return
 
        if self.client_address[0] in admin_core.BANNED_IPS:
            self.send_error(403, "Forbidden: Access revoked.")
            return
        
        is_chunk_upload = bool(
            query_params.get('filename') and query_params.get('chunk')
        )
        if not is_chunk_upload:
            if not admin_core.is_localhost(self) and not rate_limiter.is_allowed(self.client_address[0]):
                self.send_error(429, "Too Many Requests, please slow down.")
                return
    
        if not self.check_access():
            self.send_error(403, "Forbidden: Invalid Subnet")
            return

        # P2P signaling routes
        if parsed_url.path.startswith('/p2p/'):
            if peer.handle_request(self):
                return

        if parsed_url.path == '/alias':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(min(content_length, 256)).decode('utf-8')
                data      = json.loads(post_data)
                alias     = data.get('alias', '').strip()[:32]   # max 32 chars
                client_ip = self.client_address[0]
                with user_aliases_lock:
                    if alias:
                        user_aliases[client_ip] = alias
                    else:
                        # Empty submission → reset to IP
                        user_aliases.pop(client_ip, None)
                # Broadcast updated presence list regardless
                sse_broadcast("presence_update", self._build_presence_payload())
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            except Exception as e:
                print(f"Alias Error: {e}")
                self.send_error(400, "Bad Request")
            return

        if not self.has_write_access():
            self.send_error(403, "Forbidden: Access Required.")
            return

        parsed_url   = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # mkdir
        if 'action' in query_params and query_params['action'][0] == 'mkdir':
            name = query_params.get('name', [''])[0].strip()
            if name:
                target_dir = self.translate_path(parsed_url.path)
                if not os.path.isdir(target_dir):
                    target_dir = os.path.dirname(target_dir)
                try:
                    os.makedirs(os.path.join(target_dir, name), exist_ok=True)
                    _invalidate_dir_cache(os.path.join(target_dir, name))
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "ok"}')
                    
                except Exception as e:
                    self.send_error(500, f"Failed to create folder: {str(e)}")
            else:
                self.send_error(400, "Folder name is required")
            return

        if 'action' in query_params and query_params['action'][0] == 'delete':
            
            if not self.is_admin():
                self.send_error(403, "Forbidden: This action is restricted.")
                return

            file_path = self.translate_path(parsed_url.path)
            try:
                import shutil
                if os.path.isfile(file_path):
                    parent_dir = os.path.dirname(file_path)
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    parent_dir = os.path.dirname(file_path)
                    shutil.rmtree(file_path)
                else:
                    self.send_error(404, "File or folder not found")
                    return
                _invalidate_dir_cache(parent_dir)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "deleted"}')
            except PermissionError as e:
                self.send_error(423, f"File is locked and cannot be deleted: {str(e)}")
            except OSError as e:
                self.send_error(500, f"Delete failed: {str(e)}")
            return

        if 'action' in query_params and query_params['action'][0] == 'rename':
            if not self.is_admin():
                perms = _get_permissions(self.client_address[0], False)
                if not perms.get('can_rename'):
                    self.send_error(403, "Forbidden: Rename not permitted for your IP.")
                    return
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body     = json.loads(self.rfile.read(content_length).decode('utf-8'))
                old_name = body.get('old_name', '').strip()
                new_name = body.get('new_name', '').strip()
                if not old_name or not new_name:
                    self.send_error(400, "old_name and new_name are required.")
                    return
                if any(c in new_name for c in ('/', '\\', '\0')):
                    self.send_error(400, "Invalid characters in new_name.")
                    return
                # Resolve the directory being browsed (same as list_directory).
                base_path = self.translate_path(parsed_url.path)
                if not os.path.isdir(base_path):
                    base_path = os.path.dirname(base_path)
                old_path = os.path.join(base_path, old_name)
                new_path = os.path.join(base_path, new_name)
                if not os.path.exists(old_path):
                    self.send_error(404, f"Source '{old_name}' not found.")
                    return
                if os.path.exists(new_path):
                    self.send_error(409, "A file or folder with that name already exists.")
                    return
                os.rename(old_path, new_path)
                _invalidate_dir_cache(base_path)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"status": "renamed", "new_name": new_name}).encode())
            except Exception as e:
                self.send_error(500, f"Rename failed: {str(e)}")
            return

        if parsed_url.path == '/clipboard':
            CLIPBOARD_MAX_BYTES = 10_000
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > CLIPBOARD_MAX_BYTES:
                    self.send_error(
                        413,
                        f"Payload Too Large: clipboard is capped at {CLIPBOARD_MAX_BYTES} bytes.",
                    )
                    return

                post_data = self.rfile.read(content_length).decode('utf-8')
                data      = json.loads(post_data)
                text      = data.get('text', '').strip()

                # ── Strict Mode: block links from non-localhost senders ──────
                if text and admin_core.get_strict_mode():
                    client_ip = self.client_address[0]
                    local_ips = ["127.0.0.1", "::1", get_local_ip()]
                    if client_ip not in local_ips:
                        _URL_RE = re.compile(r'(https?://|www\.)', re.IGNORECASE)
                        if _URL_RE.search(text):
                            body = json.dumps({
                                "status": "error",
                                "error": "Links are disabled"
                            }).encode('utf-8')
                            self.send_response(403)
                            self.send_header('Content-type', 'application/json')
                            self.send_header('Content-Length', str(len(body)))
                            self.end_headers()
                            self.wfile.write(body)
                            return

                if text:
                    client_ip = self.client_address[0]
                    local_ips = ["127.0.0.1", "::1", get_local_ip()]

                    if client_ip in local_ips:
                        with user_aliases_lock:
                            sender = user_aliases.get(client_ip, "Server")
                    else:
                        with user_aliases_lock:
                            sender = user_aliases.get(client_ip, client_ip)

                    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                    msg       = f"[{sender}][{timestamp}]: {text}"
                    is_admin  = client_ip in local_ips
                    with clipboard_lock:
                        clipboard_messages.append({"formatted": msg, "is_admin": is_admin})
                        if len(clipboard_messages) > 100:
                            clipboard_messages.pop(0)

                    is_admin = client_ip in local_ips
                    sse_broadcast("clipboard_message", {
                        "formatted": msg,
                        "sender": sender,
                        "text": text,
                        "ts":   timestamp,
                        "is_admin":  is_admin,
                    })

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            except Exception as e:
                print(f"Clipboard Error: {e}")
                self.send_error(400, "Bad Request")
            return


        chunk_filename = query_params.get('filename', [None])[0]
        if chunk_filename:
            chunk_index = int(query_params.get('chunk', ['0'])[0])
            total_chunks = int(query_params.get('total', ['1'])[0])

            safe_name  = os.path.basename(chunk_filename)
            target_dir = self.translate_path(parsed_url.path)
            if not os.path.isdir(target_dir):
                target_dir = os.path.dirname(target_dir)
            dest_path  = os.path.join(target_dir, safe_name)

            uploader_ip = self.client_address[0]
            local_ips   = ["127.0.0.1", "::1", get_local_ip()]
            is_localhost_upload = uploader_ip in local_ips

            # ── Feature 2: Cooldown guard (chunk 0 only — new upload start) ──
            if chunk_index == 0:
                on_cooldown, secs_left = admin_core.is_ip_on_cooldown(uploader_ip)
                if on_cooldown:
                    mins = secs_left // 60
                    secs = secs_left % 60
                    self.send_error(
                        429,
                        f"Upload cooldown active. Try again in {mins}m {secs}s."
                    )
                    return

            # ── Feature 1: Cancellation blacklist (all chunks) ────────────────
            if admin_core.is_path_cancelled(dest_path):
                self.send_error(409, "Upload cancelled by admin.")
                return

            # Legacy guard: if chunk > 0 but the file is gone and not blacklisted
            if chunk_index > 0 and not os.path.exists(dest_path):
                # Allow if we are in strict-mode buffer mode (dest doesn't exist yet)
                if not (admin_core.get_strict_mode() and not is_localhost_upload):
                    self.send_error(409, "Upload cancelled by admin.")
                    return

            # Per-file lock registry
            total_bytes = int(query_params.get('total_bytes', ['0'])[0])

            if not hasattr(ModernHandler, '_chunk_locks'):
                ModernHandler._chunk_locks = {}
                ModernHandler._chunk_locks_meta = threading.Lock()
            with ModernHandler._chunk_locks_meta:
                if dest_path not in ModernHandler._chunk_locks:
                    ModernHandler._chunk_locks[dest_path] = {
                        "lock":        threading.Lock(),
                        "last_active": time.time(),
                        "uploader_ip": uploader_ip,
                        "total_bytes": total_bytes,
                    }
                lock_info = ModernHandler._chunk_locks[dest_path]
                lock_info["last_active"] = time.time()
                if total_bytes > 0:
                    lock_info["total_bytes"] = total_bytes
                file_lock = lock_info["lock"]

            content_length = int(self.headers.get('Content-Length', 0))
            chunk_data     = self.rfile.read(content_length)

            # Integrity check
            expected_hash = query_params.get('hash', [None])[0]
            if expected_hash:
                import hashlib
                actual_hash = hashlib.sha256(chunk_data).hexdigest()
                if actual_hash != expected_hash:
                    self.send_error(
                        400,
                        f"Hash mismatch on chunk {chunk_index} of '{chunk_filename}': "
                        f"expected {expected_hash}, got {actual_hash}"
                    )
                    return

            # Resolve uploader label
            if is_localhost_upload:
                with user_aliases_lock:
                    uploader_label = user_aliases.get(uploader_ip, "Server")
            else:
                with user_aliases_lock:
                    uploader_label = user_aliases.get(uploader_ip, uploader_ip)

            file_count    = int(query_params.get('file_count',    ['1'])[0])
            is_first_file = query_params.get('is_first_file', ['0'])[0] == '1'
            is_last_file  = query_params.get('is_last_file',  ['0'])[0] == '1'
            rel_path      = "/" + os.path.relpath(target_dir, FOLDER_TO_SERVE).replace("\\", "/")

            # ── Strict Mode gatekeeping (non-localhost only, chunk 0 only) ────
            if chunk_index == 0 and not is_localhost_upload and admin_core.get_strict_mode():
                import secrets as _sec
                import io as _io
                uid = _sec.token_urlsafe(12)
                ctype = self.headers.get('X-File-Type', 'application/octet-stream')

                if total_bytes > 0 and total_bytes < admin_core.STRICT_RAM_LIMIT:
                    # ── < 50 MB: buffer entire file in RAM before responding ──
                    # We must accumulate all chunks before we can tell the client
                    # to wait, so for the first chunk we start collecting and
                    # signal "pending" status. Subsequent chunks will see the
                    # pending entry and keep feeding the buffer.
                    buf = _io.BytesIO(chunk_data)
                    approved_evt = threading.Event()
                    rejected_evt = threading.Event()
                    entry = {
                        "filename":       safe_name,
                        "size":           total_bytes,
                        "content_type":   ctype,
                        "uploader_ip":    uploader_ip,
                        "uploader_label": uploader_label,
                        "dest_path":      dest_path,
                        "target_dir":     target_dir,
                        "rel_path":       rel_path,
                        "buffer":         buf,
                        "approved":       approved_evt,
                        "rejected":       rejected_evt,
                        "queued_at":      time.time(),
                        "file_count":     file_count,
                        "is_last_file":   is_last_file,
                        "total_chunks":   total_chunks,
                        "chunks_received": 1,
                    }

                    admin_core.add_to_strict_queue(uid, entry)
                    sse_broadcast("strict_pending_update", {
                        "id": uid, "filename": safe_name,
                        "size": total_bytes, "uploader_ip": uploader_ip,
                    })

                    if total_chunks > 1:
                        # Multi-chunk: respond 202 now; remaining chunks feed the
                        # RAM buffer; the last chunk blocks for admin approval.
                        self.send_response(202)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({
                            'status': 'pending',
                            'strict_id': uid,
                            'chunk': chunk_index,
                        }).encode())
                        return
                    else:
                        # Single-chunk file: the buffer is already complete.
                        # Block here waiting for admin approval (max 30 min).
                        approved = approved_evt.wait(timeout=1800)
                        if not approved or entry["rejected"].is_set():
                            admin_core.remove_from_strict_queue(uid)
                            sse_broadcast("strict_pending_update", {"removed": uid})
                            self.send_error(403, "Upload rejected by administrator.")
                            return

                        # Admin approved — flush the single-chunk buffer to disk.
                        buf = entry["buffer"]
                        buf.seek(0)
                        with file_lock:
                            with open(dest_path, 'wb') as fh:
                                fh.write(buf.read())

                        admin_core.remove_from_strict_queue(uid)
                        sse_broadcast("strict_pending_update", {"removed": uid})

                        _invalidate_dir_cache(target_dir)
                        with ModernHandler._chunk_locks_meta:
                            ModernHandler._chunk_locks.pop(dest_path, None)

                        if entry.get("is_last_file"):
                            sse_broadcast("upload_complete", {
                                "user":       uploader_label,
                                "file_count": entry.get("file_count", 1),
                                "path":       rel_path,
                            })
                        if is_first_file and chunk_index == 0:
                            sse_broadcast("upload_start", {
                                "user":       uploader_label,
                                "file_count": file_count,
                                "path":       rel_path,
                            })

                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({
                            'status': 'ok',
                            'chunk':  chunk_index,
                            'done':   True,
                        }).encode())
                        return

                else:
                    # ── ≥ 50 MB or unknown size: metadata-only hold ───────────
                    approved_evt = threading.Event()
                    rejected_evt = threading.Event()
                    entry = {
                        "filename":       safe_name,
                        "size":           total_bytes,
                        "content_type":   ctype,
                        "uploader_ip":    uploader_ip,
                        "uploader_label": uploader_label,
                        "dest_path":      dest_path,
                        "target_dir":     target_dir,
                        "rel_path":       rel_path,
                        "buffer":         None,   # too large for RAM
                        "approved":       approved_evt,
                        "rejected":       rejected_evt,
                        "queued_at":      time.time(),
                        "file_count":     file_count,
                        "is_last_file":   is_last_file,
                        "total_chunks":   total_chunks,
                        "chunks_received": 1,
                        "_first_chunk":   chunk_data,   # hold the first chunk
                    }
                    admin_core.add_to_strict_queue(uid, entry)
                    sse_broadcast("strict_pending_update", {
                        "id": uid, "filename": safe_name,
                        "size": total_bytes, "uploader_ip": uploader_ip,
                    })

                    # Block this thread until approved/rejected (max 30 min)
                    # The client will be waiting on this response
                    approved = approved_evt.wait(timeout=1800)
                    if not approved:
                        admin_core.remove_from_strict_queue(uid)
                        self.send_error(403, "Upload not approved or timed out.")
                        return
                    if entry["rejected"].is_set():
                        admin_core.remove_from_strict_queue(uid)
                        self.send_error(403, "Upload rejected by administrator.")
                        return

                    admin_core.remove_from_strict_queue(uid)
                    sse_broadcast("strict_pending_update", {"removed": uid})
                    # Fall through — write chunk to disk normally below

            # ── Handle subsequent strict-mode chunks for RAM-buffered files ──
            # Check if this upload has a pending strict entry with a buffer
            strict_entry = None
            if not is_localhost_upload and admin_core.get_strict_mode():
                # Look for an existing RAM-buffer entry for this dest_path
                with admin_core._strict_pending_lock:
                    for _uid, _entry in admin_core._strict_pending.items():
                        if _entry.get("dest_path") == dest_path and _entry.get("buffer") is not None:
                            strict_entry = (_uid, _entry)
                            break

            if strict_entry is not None:
                _uid, _entry = strict_entry
                # Accumulate chunk into RAM buffer
                _entry["buffer"].write(chunk_data)
                _entry["chunks_received"] = _entry.get("chunks_received", 0) + 1

                is_last = (chunk_index == total_chunks - 1)
                if not is_last:
                    # More chunks to come — respond ok so client keeps sending
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'status': 'buffering',
                        'strict_id': _uid,
                        'chunk': chunk_index,
                    }).encode())
                    return
                else:
                    # Last chunk received — now block waiting for admin decision
                    # (admin can already preview since buffer is complete)
                    approved_evt = _entry["approved"]
                    rejected_evt = _entry["rejected"]
                    approved = approved_evt.wait(timeout=1800)
                    if not approved or rejected_evt.is_set():
                        admin_core.remove_from_strict_queue(_uid)
                        sse_broadcast("strict_pending_update", {"removed": _uid})
                        self.send_error(403, "Upload rejected by administrator.")
                        return

                    # Admin approved — flush buffer to disk
                    buf = _entry["buffer"]
                    buf.seek(0)
                    with file_lock:
                        with open(dest_path, 'wb') as fh:
                            fh.write(buf.read())

                    admin_core.remove_from_strict_queue(_uid)
                    sse_broadcast("strict_pending_update", {"removed": _uid})

                    _invalidate_dir_cache(target_dir)
                    with ModernHandler._chunk_locks_meta:
                        ModernHandler._chunk_locks.pop(dest_path, None)

                    if _entry.get("is_last_file"):
                        sse_broadcast("upload_complete", {
                            "user":       uploader_label,
                            "file_count": _entry.get("file_count", 1),
                            "path":       rel_path,
                        })
                    if is_first_file and chunk_index == 0:
                        sse_broadcast("upload_start", {
                            "user":       uploader_label,
                            "file_count": file_count,
                            "path":       rel_path,
                        })

                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'status': 'ok',
                        'chunk':  chunk_index,
                        'done':   True,
                    }).encode())
                    return

            # ── Normal (non-strict or localhost) path ─────────────────────────
            if is_first_file and chunk_index == 0:
                sse_broadcast("upload_start", {
                    "user":       uploader_label,
                    "file_count": file_count,
                    "path":       rel_path,
                })

            with file_lock:
                # First chunk truncates any leftover partial file.
                mode = 'wb' if chunk_index == 0 else 'ab'
                with open(dest_path, mode) as fh:
                    fh.write(chunk_data)

            is_last = (chunk_index == total_chunks - 1)
            if is_last:
                # All chunks received — invalidate directory cache.
                _invalidate_dir_cache(target_dir)
                with ModernHandler._chunk_locks_meta:
                    ModernHandler._chunk_locks.pop(dest_path, None)

                if is_last_file:
                    sse_broadcast("upload_complete", {
                        "user":       uploader_label,
                        "file_count": file_count,
                        "path":       rel_path,
                    })

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'status': 'ok',
                'chunk':  chunk_index,
                'done':   is_last,
            }).encode())
            return
        # File upload — streaming multipart parser
        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('multipart/form-data'):
            self.send_error(400, "Bad Request: Expected multipart form data")
            return

        try:
            ct_parts = content_type.split('boundary=', 1)
            if len(ct_parts) < 2:
                self.send_error(400, "Bad Request: Missing multipart boundary")
                return

            boundary  = ct_parts[1].strip().encode()
            delimiter = b'--' + boundary
            CHUNK     = 65536

            target_dir = self.translate_path(self.path)
            if not os.path.isdir(target_dir):
                target_dir = os.path.dirname(target_dir)

            uploaded_files  = []
            error_response  = None
            buf             = b''
            in_file_part    = False
            current_file    = None
            current_name    = ''
            current_size    = 0
            skip_part       = False
            content_length  = int(self.headers.get('Content-Length', 0))
            bytes_remaining = content_length

            def close_current_file(trim_tail=True):
                nonlocal current_file, current_size
                if current_file:
                    if trim_tail:
                        pos = current_file.tell()
                        if pos >= 2:
                            current_file.seek(pos - 2)
                            current_file.truncate()
                    current_file.close()
                    current_file = None
                    current_size = 0

            while bytes_remaining > 0 or buf:
                if bytes_remaining > 0:
                    try:
                        chunk = self.rfile.read(min(CHUNK, bytes_remaining))
                    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                        chunk = b''
                        
                    if not chunk:
                        error_response = (400, "Connection dropped prematurely")
                        break
                        
                    bytes_remaining -= len(chunk)
                    buf             += chunk

                keep = len(delimiter) + 6

                while True:
                    if not in_file_part:
                        idx = buf.find(delimiter)
                        if idx == -1:
                            if bytes_remaining == 0:
                                break
                            buf = buf[-keep:]
                            break

                        after = idx + len(delimiter)
                        if buf[after:after + 2] == b'--':
                            buf = b''
                            break
                        if buf[after:after + 2] != b'\r\n':
                            if bytes_remaining == 0:
                                break
                            buf = buf[-keep:]
                            break

                        buf = buf[after + 2:]

                        headers_end = buf.find(b'\r\n\r\n')
                        if headers_end == -1:
                            if bytes_remaining == 0:
                                break
                            buf = buf[-keep:]
                            break

                        part_headers = buf[:headers_end].decode('utf-8', errors='replace')
                        buf          = buf[headers_end + 4:]

                        filename = None
                        for hdr_line in part_headers.splitlines():
                            if hdr_line.lower().startswith('content-disposition'):
                                m = re.search(r'filename="([^"]*)"', hdr_line, re.IGNORECASE)
                                if m:
                                    filename = m.group(1)
                                if 'name="files[]"' not in hdr_line:
                                    filename = None
                                break

                        if filename:
                            safe_filename = os.path.basename(filename)
                            _, ext        = os.path.splitext(safe_filename)
                            if not safe_filename or ext.lower() in EXCLUDED_UPLOAD_EXT:
                                error_response = (400, f"Upload failed: File type '{ext}' is marked Unsafe")
                                self.rfile.read(bytes_remaining)
                                bytes_remaining = 0
                                buf = b''
                                break
                            current_file = open(os.path.join(target_dir, safe_filename), 'wb')
                            current_name = safe_filename
                            current_size = 0
                            in_file_part = True
                            skip_part    = False
                        else:
                            in_file_part = True
                            skip_part    = True

                    else:
                        idx = buf.find(b'\r\n' + delimiter)
                        if idx == -1:
                            if bytes_remaining == 0:
                                if not skip_part and current_file:
                                    current_file.write(buf)
                                    current_size += len(buf)
                                buf = b''
                                break
                            safe_len = len(buf) - keep
                            if safe_len > 0:
                                safe_data = buf[:safe_len]
                                if not skip_part and current_file:
                                    if current_size + len(safe_data) > MAX_UPLOAD_MB * 1024 * 1024:
                                        close_current_file(trim_tail=False)
                                        partial = os.path.join(target_dir, current_name)
                                        if current_name and os.path.exists(partial):
                                            os.remove(partial)
                                        error_response = (400, f"Upload failed: File exceeds {MAX_UPLOAD_MB} MB")
                                        self.rfile.read(bytes_remaining)
                                        bytes_remaining = 0
                                        buf = b''
                                        in_file_part = False
                                        break
                                    current_file.write(safe_data)
                                    current_size += len(safe_data)
                                buf = buf[safe_len:]
                            break

                        body_data = buf[:idx]
                        if not skip_part and current_file:
                            if current_size + len(body_data) > MAX_UPLOAD_MB * 1024 * 1024:
                                close_current_file(trim_tail=False)
                                partial = os.path.join(target_dir, current_name)
                                if current_name and os.path.exists(partial):
                                    os.remove(partial)
                                error_response = (400, f"Upload failed: File exceeds {MAX_UPLOAD_MB} MB")
                                self.rfile.read(bytes_remaining)
                                bytes_remaining = 0
                                buf = b''
                                in_file_part = False
                                break
                            current_file.write(body_data)
                            current_size += len(body_data)

                        if not skip_part and current_file:
                            close_current_file(trim_tail=False)
                            uploaded_files.append(current_name)
                            current_name = ''

                        buf          = buf[idx + 2:]
                        in_file_part = False
                        skip_part    = False

                if error_response:
                    break

            if current_file:
                close_current_file(trim_tail=False)
                # Only add to uploaded_files if the loop naturally finished without errors
                if not skip_part and current_name and not error_response:
                    uploaded_files.append(current_name)

            if error_response:
                # Cleanup the orphaned file on expected errors or connection drops
                if current_name:
                    partial = os.path.join(target_dir, current_name)
                    if os.path.exists(partial):
                        os.remove(partial)
                self.send_error(*error_response)
                return

            if uploaded_files:
                _invalidate_dir_cache(os.path.join(target_dir, name))
                self.send_response(303)
                self.send_header('Location', self.path)
                self.end_headers()
            else:
                self.send_error(400, "No valid files found")

        except Exception as e:
            print(f"Upload error: {e}")
            # Failsafe cleanup for unexpected crashes
            if 'current_file' in locals() and current_file:
                try:
                    current_file.close()
                except Exception:
                    pass
            if 'current_name' in locals() and current_name:
                partial = os.path.join(target_dir, current_name)
                if os.path.exists(partial):
                    try:
                        os.remove(partial)
                    except OSError:
                        pass
            self.send_error(500, f"Upload failed: {str(e)}")

        except Exception as e:
            print(f"Upload error: {e}")
            self.send_error(500, f"Upload failed: {str(e)}")


    def list_directory(self, path):
        try:
            list_dir = _cached_listdir(path)
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None

        # Apply admin-managed exclusions before anything downstream (rows, subtitles, gallery) sees these names.
        list_dir = [name for name in list_dir if not _is_admin_excluded(os.path.join(path, name), name)]

        sort_by = 'name'
        try:
            sort_param = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            ).get('sort', ['name'])[0]
            if sort_param in ['name', 'size', 'date', 'type']:
                sort_by = sort_param
        except Exception:
            pass

        existing_files = set(list_dir)
        all_subtitles  = [f for f in list_dir if f.lower().endswith(('.srt', '.vtt'))]
        file_data      = []
        gallery_images = []

        for name in list_dir:
            fullname  = os.path.join(path, name)
            is_dir    = os.path.isdir(fullname)
            size, mtime = 0, 0
            ext       = os.path.splitext(name)[1].lower()

            subtitle_file = None
            if not is_dir and ext in MEDIA_EXTS['video']:
                base = os.path.splitext(name)[0]
                if f"{base}.srt" in existing_files:
                    subtitle_file = f"{base}.srt"
                elif f"{base}.vtt" in existing_files:
                    subtitle_file = f"{base}.vtt"

            if os.path.isfile(fullname):
                try:
                    size  = os.path.getsize(fullname)
                    mtime = os.path.getmtime(fullname)
                except OSError:
                    pass
            elif is_dir:
                try:
                    mtime = os.path.getmtime(fullname)
                except OSError:
                    pass

            file_data.append({
                'name': name, 'is_dir': is_dir, 'size': size,
                'mtime': mtime, 'type': 'folder' if is_dir else 'file',
                'ext': ext, 'subtitle': subtitle_file,
            })
            if not is_dir and ext in MEDIA_EXTS['image']:
                gallery_images.append({'name': name, 'url': urllib.parse.quote(name)})

        if sort_by == 'name':
            file_data.sort(key=lambda x: x['name'].lower())
        elif sort_by == 'size':
            file_data.sort(key=lambda x: x['size'], reverse=True)
            file_data.sort(key=lambda x: not x['is_dir'])
        elif sort_by == 'date':
            file_data.sort(key=lambda x: x['mtime'], reverse=True)
        elif sort_by == 'type':
            file_data.sort(key=lambda x: (x['type'], x['ext'], x['name'].lower()))

        write_access = self.has_write_access()
        parsed_url   = urllib.parse.urlparse(self.path)
        clean_path   = parsed_url.path
        displaypath  = html.escape(urllib.parse.unquote(clean_path))
       
        dir_url_prefix = clean_path if clean_path.endswith('/') else clean_path + '/'

        # Build file rows
        file_rows = []
        for item in file_data:
            name, is_dir, ext = item['name'], item['is_dir'], item['ext']
            # Exclusion filtering already happened on list_dir above.

            linkname   = name + "/" if is_dir else name
            icon_class = "icon-gray"
            icon_text  = ext.replace('.', '').upper()[:3]
            if is_dir:                                   icon_class, icon_text = "icon-folder", ""
            elif ext == '.pdf':                          icon_class = "icon-red"
            elif ext in ['.doc', '.docx', '.txt']:      icon_class = "icon-blue"
            elif ext in ['.xls', '.xlsx', '.csv']:      icon_class = "icon-green"
            elif ext in ['.ppt', '.pptx']:              icon_class = "icon-yellow"
            elif ext in MEDIA_EXTS['video']:             icon_class = "icon-purple"
            elif ext in MEDIA_EXTS['image']:             icon_class = "icon-teal"
            elif ext in ['.zip', '.rar', '.7z']:         icon_class = "icon-orange"

            media_type = ('video' if ext in MEDIA_EXTS['video'] else
                          'audio' if ext in MEDIA_EXTS['audio'] else
                          'image' if ext in MEDIA_EXTS['image'] else None)
            type_desc  = "Folder" if is_dir else (f"{ext.upper()[1:]} File" if ext else "File")

            size_str = "--"
            if not is_dir:
                try:
                    s = item['size']
                    for u in ['B', 'KB', 'MB', 'GB']:
                        if s < 1024:
                            size_str = f"{s:.1f} {u}"
                            break
                        s /= 1024
                except Exception:
                    pass

            try:
                date_str = datetime.datetime.fromtimestamp(item['mtime']).strftime('%Y-%m-%d %H:%M')
            except Exception:
                date_str = "Unknown"

            url       = dir_url_prefix + urllib.parse.quote(linkname)
            grid_meta = type_desc if is_dir else size_str

            if is_dir:
                file_rows.append(
                    f'<a href="{url}" class="item" data-name="{name.lower()}" data-url="{url}" data-type="dir">'
                    f'<div class="file-icon {icon_class}">{icon_text}</div>'
                    f'<div class="info"><span class="name">{html.escape(name)}</span>'
                    f'<span class="meta grid-meta">{grid_meta}</span>'
                    f'<span class="meta list-meta type">{type_desc}</span>'
                    f'<span class="meta list-meta size">{size_str}</span>'
                    f'<span class="meta date">{date_str}</span></div></a>'
                )
            else:
                can_prev = 'true' if ext in PREVIEWABLE_EXTS else 'false'
                m_attr   = f"'{media_type}'" if media_type else 'null'
                sub_url  = f"'{dir_url_prefix + urllib.parse.quote(item['subtitle'])}'" if item.get('subtitle') else 'null'
                subs_enc = urllib.parse.quote(json.dumps([dir_url_prefix + urllib.parse.quote(s) for s in all_subtitles]))
                file_rows.append(
                    f'<div class="item" data-name="{name.lower()}" data-url="{url}" data-type="file" '
                    f'onclick="showModal(\'{url}\',\'{name}\',{can_prev},{m_attr},{sub_url},\'{subs_enc}\')">'
                    f'<div class="file-icon {icon_class}">{icon_text}</div>'
                    f'<div class="info"><span class="name">{html.escape(name)}</span>'
                    f'<span class="meta grid-meta">{grid_meta}</span>'
                    f'<span class="meta list-meta type">{type_desc}</span>'
                    f'<span class="meta list-meta size">{size_str}</span>'
                    f'<span class="meta date">{date_str}</span></div></div>'
                )

        # Breadcrumb
        breadcrumb_parts = ['<a href="/">Home</a>']
        for part in clean_path.strip('/').split('/'):
            if part:
                breadcrumb_parts.append(
                    f'<span class="breadcrumb-sep">></span>'
                    f'<span>{html.escape(urllib.parse.unquote(part))}</span>'
                )

        # Conditional HTML fragments
        if write_access:
            clipboard_input_html = (
                '<div class="cb-input-area">'
                '<textarea id="cb-input" placeholder="Type a message..."></textarea>'
                '<button onclick="sendClipboard()">Send</button>'
                '</div>'
            )
        else:
            clipboard_input_html = (
                '<div style="text-align:center;color:#888;font-size:14px;padding:10px;">'
                'Read-Only Mode</div>'
            )

        write_buttons_html = (
            '<button class="folder-btn" onclick="createFolder()">New Folder</button>'
            '<button class="upload-btn" onclick="showUploadForm()">&#11014;&#65039; Upload</button>'
        ) if write_access else ''

        # Load template and inject
        try:
            with open(TEMPLATE_PATH, 'r', encoding='utf-8') as tf:
                page = tf.read()
        except OSError as e:
            self.send_error(500, f"Template not found: {e}")
            return None

        page = page.replace('{TITLE}', f"Files: {displaypath}")
        page = page.replace('{BREADCRUMB}', ''.join(breadcrumb_parts))
        page = page.replace('{CLIPBOARD_INPUT}', clipboard_input_html)
        page = page.replace('{WRITE_BUTTONS}', write_buttons_html)
        page = page.replace('{FILE_ROWS}', '\n'.join(file_rows))
        page = page.replace('{GALLERY_JSON}',      json.dumps(gallery_images))
        page = page.replace('{USER_PERMISSIONS}',  json.dumps(_get_permissions(self.client_address[0], self.is_admin())))
        page = page.replace('{CURRENT_PATH}', displaypath)

        client_ip   = self.client_address[0]
        host_admin  = self.is_admin()
        page = page.replace('{IS_ADMIN}', 'true' if host_admin else 'false')
        csrf_tok    = admin_core.ADMIN_CSRF_TOKEN if host_admin else ''
        page = page.replace('{ADMIN_CSRF_TOKEN}', csrf_tok)
       
        # Encode and send the final HTML
        encoded = page.encode('utf-8', 'surrogateescape')
        buf     = io.BytesIO(encoded)
        buf.seek(0)
        
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if host_admin:
            self.send_header(
                "Set-Cookie",
                f"admin_session={admin_core.ADMIN_SESSION_SECRET}; Path=/; HttpOnly; SameSite=Strict",
            )
            self.send_header(
                "Set-Cookie",
                f"admin_csrf={admin_core.ADMIN_CSRF_TOKEN}; Path=/; SameSite=Strict",
            )
        self.end_headers()
        return buf


admin_core.init({
    **globals(),
    "__file__": __file__,
    "ModernHandler": ModernHandler,
})

peer.init({
    **globals(),
    "__file__": __file__,
    "ModernHandler": ModernHandler,
})

def run_server():
    if not os.path.exists(FOLDER_TO_SERVE):
        print(f"Error: Path not found: {FOLDER_TO_SERVE}")
        return
    try:
        os.chdir(FOLDER_TO_SERVE)
    except Exception as e:
        print(f"Error accessing folder: {e}")
        return

    if not os.path.exists(TEMPLATE_PATH):
        print(f"Error: Template not found at {TEMPLATE_PATH}")
        print("Ensure index.html is in the same directory as server.py")
        return

    global PORT
    current_port = PORT
    while True:
        try:
            httpd = ThreadedTCPServer(("", current_port), ModernHandler)
            # Wrap with TLS.
            
            CERT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert.pem")
            KEY_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.pem")
            if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
                httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
                _protocol = "https"
                print("HTTPS enabled")
            else:
                _protocol = "http"
                print("HTTPS not enabled")
            break
        except OSError as e:
            if e.errno in (98, 10048):
                current_port += 1
            else:
                raise

    try:
        local_ip   = get_local_ip()
        auth_param = f"?auth={SECRET_TOKEN}"
        print(f"\n{'_' * 60}")
        print("SERVER STARTED")
        print(f"Port: {current_port}")
        print(f"Host Admin Link: {_protocol}://127.0.0.1:{current_port}/{auth_param}")
        print(f"Network URL (Scan QR): {_protocol}://{local_ip}:{current_port}/{auth_param}")
        display_qr_code(f"{_protocol}://{local_ip}:{current_port}/{auth_param}")

        print("Press Ctrl+C to stop the server")
        print(f"{'_' * 60}\n")

        # zeroconfig
        zc = None
        zc_info = None
        if ZEROCONF_AVAILABLE:
            try:
                local_ip_bytes = socket.inet_aton(local_ip)
                zc_info = ServiceInfo(
                    "_http._tcp.local.",
                    f"FileServer._http._tcp.local.",
                    addresses=[local_ip_bytes],
                    port=current_port,
                    properties={"path": "/"},
                )
                zc = Zeroconf()
                zc.register_service(zc_info)
                print(f"mDNS: advertising as 'FileServer._http._tcp.local.' on port {current_port}")
            except Exception as e:
                print(f"mDNS registration failed: {e}")

        _sweeper_thread = start_stale_lock_sweeper(ModernHandler)

        try:
            httpd.serve_forever()

        except KeyboardInterrupt:
            print("\nServer stopped.")

        finally:
            # zeroconf shutdown
            if zc and zc_info:
                try:
                    zc.unregister_service(zc_info)
                    zc.close()
                    print("mDNS service unregistered.")
                except Exception:
                    pass
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    if segno is None:
        print("Warning: 'segno' not installed — QR code feature disabled.")
    run_server()
