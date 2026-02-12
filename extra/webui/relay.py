#!/usr/bin/env python3
"""
sqlmap Browser Relay

Routes sqlmap's HTTP requests through a remote browser.
This lets sqlmap test targets that are only reachable from the browser's machine.

Usage:
  1. Start relay:  sudo python3 sqlmap.py --web-relay
  2. Open browser:  http://YOUR_MACBOOK_IP/ on the remote machine
  3. Fill in target details and click Start Scan
"""

import argparse
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs

# ── Config (set in main()) ───────────────────────────────────────────────────

PROXY_PORT = 8888
SQLMAP_PATH = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "..", "sqlmap.py"))

# ── Shared State – relay queue ───────────────────────────────────────────────

pending_requests = {}
pending_lock = threading.Lock()
relay_stats = {"relayed": 0, "errors": 0}

# ── Shared State – scan management ───────────────────────────────────────────

scan_process = None
scan_output = []           # list of str lines
scan_output_lock = threading.Lock()
scan_status = "idle"       # idle | running | finished | error | stopped
pending_question = None     # {"text": "...", "event": Event} or None
question_lock = threading.Lock()

# ── SSL Certificates (for HTTPS target interception) ─────────────────────────

CERT_DIR = None
CA_KEY = None
CA_CERT = None
CERTS_AVAILABLE = False

_cert_cache = {}
_cert_lock = threading.Lock()


def init_certs():
    """Generate a throwaway CA for HTTPS CONNECT interception."""
    global CERT_DIR, CA_KEY, CA_CERT, CERTS_AVAILABLE
    CERT_DIR = tempfile.mkdtemp(prefix="sqlmap_relay_certs_")
    CA_KEY = os.path.join(CERT_DIR, "ca.key")
    CA_CERT = os.path.join(CERT_DIR, "ca.crt")

    try:
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-days", "1",
             "-keyout", CA_KEY, "-out", CA_CERT,
             "-subj", "/CN=sqlmap Relay CA", "-nodes"],
            check=True, capture_output=True
        )
        CERTS_AVAILABLE = True
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        print(f"  [!] openssl unavailable ({exc}) – HTTPS targets won't work")


def get_cert(hostname):
    """Return (key_path, cert_path) for *hostname*, generating on first use."""
    with _cert_lock:
        if hostname in _cert_cache:
            return _cert_cache[hostname]

    key = os.path.join(CERT_DIR, f"{hostname}.key")
    cert = os.path.join(CERT_DIR, f"{hostname}.crt")
    csr = os.path.join(CERT_DIR, f"{hostname}.csr")
    cnf = os.path.join(CERT_DIR, f"{hostname}.cnf")

    with open(cnf, "w") as f:
        f.write(f"[req]\ndistinguished_name=dn\n[dn]\n"
                f"[san]\nsubjectAltName=DNS:{hostname}\n")

    subprocess.run(["openssl", "genrsa", "-out", key, "2048"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-key", key, "-out", csr,
                    "-subj", f"/CN={hostname}", "-config", cnf],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", csr,
                    "-CA", CA_CERT, "-CAkey", CA_KEY, "-CAcreateserial",
                    "-out", cert, "-days", "1",
                    "-extfile", cnf, "-extensions", "san"],
                   check=True, capture_output=True)

    with _cert_lock:
        _cert_cache[hostname] = (key, cert)
    return key, cert


# ── Request Queue ────────────────────────────────────────────────────────────

SKIP_HEADERS = frozenset([
    "host", "connection", "proxy-connection", "proxy-authorization",
    "transfer-encoding", "content-length", "keep-alive", "upgrade",
    "te", "trailer",
])


def queue_request(method, url, headers, body, timeout=120):
    """Add a request to the queue and block until the browser responds."""
    req_id = str(uuid.uuid4())
    event = threading.Event()

    relay_headers = {}
    for k, v in headers.items():
        if k.lower() not in SKIP_HEADERS:
            relay_headers[k] = v

    with pending_lock:
        pending_requests[req_id] = {
            "method": method,
            "url": url,
            "headers": relay_headers,
            "body": body,
            "event": event,
            "claimed": False,
            "response": None,
            "time": time.time(),
        }

    print(f"  [QUEUE]  {method} {url[:100]} (id={req_id[:8]})")
    event.wait(timeout=timeout)

    with pending_lock:
        req_data = pending_requests.pop(req_id, None)

    if req_data and req_data.get("response"):
        relay_stats["relayed"] += 1
        return req_data["response"]

    relay_stats["errors"] += 1
    return None


# ── Scan Management ──────────────────────────────────────────────────────────

# Protocol marker for reliable question detection.
# Instead of guessing prompts from stdout text, we monkeypatch sqlmap's
# readInput() to emit this marker before blocking on stdin.
QUESTION_MARKER = "\x02RELAY_Q:"
QUESTION_END    = "\x03"

# The boot script injected into the sqlmap subprocess.  It patches
# readInput() so every interactive question is signalled over the pipe
# with a deterministic marker that the relay can detect with 100% certainty.
def _write_boot_script():
    """Write the boot script that patches readInput before running sqlmap.

    The boot script lives at the sqlmap root (not in extra/webui/) so that
    modulePath() resolves correctly.
    """
    boot_path = os.path.join(
        os.path.dirname(SQLMAP_PATH), "_relay_boot.py")

    content = r'''#!/usr/bin/env python3
"""Boot wrapper that patches readInput() for the relay, then runs sqlmap."""
import sys, os

# This file sits in the sqlmap root, so __file__-based path detection works.
# We just need to patch readInput before sqlmap's main() calls it.

_sqlmap_root = os.path.dirname(os.path.abspath(__file__))
if _sqlmap_root not in sys.path:
    sys.path.insert(0, _sqlmap_root)

# ── Deferred patching ───────────────────────────────────────────────────
# We can't import lib.core.common yet (sqlmap hasn't set up paths).
# Instead, we hook into the import system to patch readInput as soon as
# lib.core.common is loaded.

import importlib
_original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__
_patched = False

def _patching_import(name, *args, **kwargs):
    global _patched
    mod = _original_import(name, *args, **kwargs)
    if not _patched and name == "lib.core.common" and hasattr(mod, "readInput"):
        _patched = True
        _do_patch(mod)
    return mod

def _do_patch(_common):
    # Prevent sqlmap from auto-enabling batch mode when stdin is a pipe.
    # sqlmap calls checkPipedInput() and sets conf.batch=True if stdin
    # is not a TTY.  We override it to return False so sqlmap stays
    # interactive and actually calls readInput().
    _common.checkPipedInput = lambda: False

    def _relay_readInput(message, default=None, checkBatch=True, boolean=False):
        import sys as _sys
        from lib.core.data import conf, kb
        from lib.core.convert import getUnicode
        from lib.core.settings import UNICODE_ENCODING
        import six

        retVal = None
        message = getUnicode(message)

        if "\n" in message:
            message += "%s> " % ("\n" if message.count("\n") > 1 else "")
        elif message[-1] == ']':
            message += " "

        if kb.get("prependFlag"):
            message = "\n%s" % message
            kb.prependFlag = False

        # Handle --answers
        if conf.get("answers"):
            if not any(_ in conf.answers for _ in ",="):
                return conf.answers
            for item in conf.answers.split(','):
                question = item.split('=')[0].strip()
                answer = item.split('=')[1] if len(item.split('=')) > 1 else None
                if answer and question.lower() in message.lower():
                    retVal = getUnicode(answer, UNICODE_ENCODING)
                elif answer is None and retVal:
                    retVal = "%s,%s" % (retVal, getUnicode(item, UNICODE_ENCODING))

        if retVal:
            _sys.stdout.write("%s%s\n" % (message, retVal))
            _sys.stdout.flush()
            return retVal

        # Handle --batch / --api / --non-interactive
        if checkBatch and conf.get("batch") or any(conf.get(_) for _ in ("api", "nonInteractive")):
            from lib.core.common import isListLike
            if isListLike(default):
                options = ','.join(getUnicode(opt, UNICODE_ENCODING) for opt in default)
            elif default:
                options = getUnicode(default, UNICODE_ENCODING)
            else:
                options = six.text_type()
            _sys.stdout.write("%s%s\n" % (message, options))
            _sys.stdout.flush()
            return default

        # ── Interactive: signal the relay ──────────────────────────────
        # Write prompt text normally (appears in the relay log)
        _sys.stdout.write(message)
        _sys.stdout.flush()

        # Protocol marker – the relay detects this with certainty.
        # Escape internal newlines so the marker stays on ONE line.
        _safe_msg = message.strip().replace("\n", "\\n")
        _sys.stdout.write("\x02RELAY_Q:" + _safe_msg + "\x03\n")
        _sys.stdout.flush()

        # Block on stdin until the relay writes the user's answer
        try:
            retVal = _sys.stdin.readline().strip()
        except Exception:
            from lib.core.exception import SqlmapUserQuitException
            raise SqlmapUserQuitException

        if not retVal:
            _sys.stdout.write("\n")
            _sys.stdout.flush()
        retVal = retVal or default
        retVal = getUnicode(retVal, encoding=getattr(_sys.stdin, "encoding", None)) if retVal else retVal

        kb.prependFlag = False
        return retVal

    _common.readInput = _relay_readInput

# Install the import hook
import builtins
builtins.__import__ = _patching_import

# ── Run the real sqlmap.py ──────────────────────────────────────────────
_sqlmap_main = os.path.join(_sqlmap_root, "sqlmap.py")
# exec in a namespace where __file__ = sqlmap.py so modulePath() works
_ns = {"__name__": "__main__", "__file__": _sqlmap_main, "__builtins__": __builtins__}
with open(_sqlmap_main) as _f:
    exec(compile(_f.read(), _sqlmap_main, "exec"), _ns)
'''
    with open(boot_path, "w") as f:
        f.write(content)
    return boot_path


def start_scan(config):
    """Spawn sqlmap with the given config, routing through our proxy."""
    global scan_process, scan_output, scan_status

    if scan_process and scan_process.poll() is None:
        return False, "A scan is already running"

    url = (config.get("url") or "").strip()
    if not url:
        return False, "Target URL is required"

    scan_output = []
    scan_status = "running"

    # Build the argument list (without the python/sqlmap prefix — the boot
    # script handles that).
    args = []
    args.extend(["-u", url])
    args.extend(["--proxy", f"http://127.0.0.1:{PROXY_PORT}"])
    args.append("--disable-coloring")  # ANSI codes garble the HTML log

    # Relay-aware defaults: the browser relay adds 0.5-3s of latency per
    # request (poll interval + network hops), so we must tune timing:
    args.extend(["--time-sec", "10"])   # default 5 is too short through relay
    args.extend(["--timeout", "60"])    # default 30 may timeout through relay
    args.extend(["--retries", "3"])     # retry on transient relay failures

    if config.get("data"):
        args.extend(["--data", config["data"]])
    if config.get("cookie"):
        args.extend(["--cookie", config["cookie"]])
    if config.get("technique"):
        args.extend(["--technique", config["technique"]])
    if config.get("level"):
        lvl = int(config["level"])
        if lvl > 1:
            args.extend(["--level", str(lvl)])
    if config.get("risk"):
        rsk = int(config["risk"])
        if rsk > 1:
            args.extend(["--risk", str(rsk)])
    if config.get("threads"):
        thr = int(config["threads"])
        if thr > 1:
            args.extend(["--threads", str(thr)])
    if config.get("verbose"):
        v = int(config["verbose"])
        if v != 1:
            args.extend(["-v", str(v)])
    if config.get("randomAgent"):
        args.append("--random-agent")
    if config.get("flushSession"):
        args.append("--flush-session")
    if config.get("extra"):
        try:
            args.extend(shlex.split(config["extra"]))
        except ValueError:
            pass

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"  # ensure prompts arrive immediately
    if url.startswith("https://"):
        env["PYTHONHTTPSVERIFY"] = "0"

    # Write the boot script to the sqlmap root (so __file__-based path
    # detection in modulePath() resolves correctly).
    boot_script = _write_boot_script()

    cmd = [sys.executable, boot_script] + args
    cmd_str = " ".join(cmd)
    with scan_output_lock:
        scan_output.append(f"[relay] {cmd_str}")

    try:
        scan_process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0, env=env,
        )
    except Exception as exc:
        scan_status = "error"
        with scan_output_lock:
            scan_output.append(f"[relay] Failed to start: {exc}")
        return False, str(exc)

    def _handle_question(text):
        """Block the reader until the user answers via the web UI."""
        global pending_question
        event = threading.Event()
        with question_lock:
            pending_question = {"text": text, "event": event}
        event.wait(timeout=300)
        with question_lock:
            pending_question = None

    def reader():
        global scan_status, pending_question
        try:
            buf = b""

            while True:
                ch = scan_process.stdout.read(1)
                if not ch:
                    # EOF – flush remaining buffer
                    if buf.strip():
                        try:
                            line = buf.decode("utf-8", errors="replace").rstrip("\n\r")
                            # Don't show protocol markers in the log
                            if QUESTION_MARKER not in line:
                                with scan_output_lock:
                                    scan_output.append(line)
                        except Exception:
                            pass
                    break

                buf += ch

                if ch == b'\n':
                    try:
                        line = buf.decode("utf-8", errors="replace").rstrip("\n\r")
                    except Exception:
                        line = ""
                    buf = b""

                    if not line:
                        continue

                    # Check for the reliable protocol marker
                    if QUESTION_MARKER in line:
                        start = line.index(QUESTION_MARKER) + len(QUESTION_MARKER)
                        end = line.index(QUESTION_END) if QUESTION_END in line else len(line)
                        raw = line[start:end].strip()
                        # Unescape newlines, then find the actual question.
                        # Multi-line messages look like:
                        #   [1/1] URL:\nGET http://...\ndo you want...? [Y/n]\n>
                        # We want the line with "?" or "[Y/n]", not ">".
                        parts = [p.strip() for p in raw.replace("\\n", "\n").split("\n") if p.strip()]
                        # Pick the last line that looks like a question;
                        # fall back to the whole message if none match.
                        question_text = raw.replace("\\n", " ")
                        for part in reversed(parts):
                            if "?" in part or "[" in part:
                                question_text = part
                                break
                        if question_text:
                            _handle_question(question_text)
                    else:
                        with scan_output_lock:
                            scan_output.append(line)

            scan_process.wait()
            code = scan_process.returncode
            with scan_output_lock:
                scan_output.append(f"[relay] sqlmap exited (code {code})")
            if scan_status != "stopped":
                scan_status = "finished" if code == 0 else "error"
        except Exception as exc:
            if scan_status != "stopped":
                scan_status = "error"
            with scan_output_lock:
                scan_output.append(f"[relay] reader error: {exc}")

    threading.Thread(target=reader, daemon=True).start()
    return True, cmd_str


def stop_scan():
    """Terminate the running sqlmap process."""
    global scan_process, scan_status
    if scan_process and scan_process.poll() is None:
        scan_status = "stopped"

        # Release any pending question so the reader thread unblocks
        with question_lock:
            if pending_question:
                pending_question["event"].set()

        scan_process.terminate()
        try:
            scan_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            scan_process.kill()

        with scan_output_lock:
            scan_output.append("[relay] Scan stopped by user")
        return True
    return False


# ── HTTP Proxy (sqlmap connects here) ────────────────────────────────────────

class ProxyHandler(BaseHTTPRequestHandler):
    """Minimal HTTP/HTTPS proxy that queues every request for the browser."""

    def do_GET(self):     self._handle("GET")
    def do_POST(self):    self._handle("POST")
    def do_PUT(self):     self._handle("PUT")
    def do_DELETE(self):  self._handle("DELETE")
    def do_HEAD(self):    self._handle("HEAD")
    def do_PATCH(self):   self._handle("PATCH")
    def do_OPTIONS(self): self._handle("OPTIONS")

    # ── HTTPS CONNECT ────────────────────────────────────────────────────
    def do_CONNECT(self):
        if not CERTS_AVAILABLE:
            self.send_error(501, "HTTPS not available (openssl missing)")
            return

        host_port = self.path
        hostname = host_port.split(":")[0]

        try:
            key_file, cert_file = get_cert(hostname)
        except Exception as exc:
            self.send_error(502, f"Cert generation failed: {exc}")
            return

        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)

        try:
            tls = ctx.wrap_socket(self.connection, server_side=True)
        except ssl.SSLError as exc:
            print(f"  [SSL]    Handshake failed for {hostname}: {exc}")
            return

        try:
            self._tunnel(tls, hostname)
        except Exception as exc:
            print(f"  [TUNNEL] {hostname}: {exc}")
        finally:
            try:
                tls.close()
            except Exception:
                pass

    def _tunnel(self, tls, hostname):
        """Handle multiple HTTP requests inside a CONNECT tunnel (keep-alive)."""
        rfile = tls.makefile("rb")

        while True:
            # Read request line
            request_line = rfile.readline()
            if not request_line:
                return  # Connection closed
            line_str = request_line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue  # Skip empty lines between keep-alive requests
            parts = line_str.split(" ", 2)
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]

            # Read headers
            headers = {}
            while True:
                hline = rfile.readline().decode("utf-8", errors="replace").strip()
                if not hline:
                    break
                if ": " in hline:
                    k, v = hline.split(": ", 1)
                    headers[k] = v

            # Read body
            cl = int(headers.get("Content-Length", 0))
            body = rfile.read(cl).decode("utf-8", errors="replace") if cl else ""

            host = headers.get("Host", hostname)
            url = f"https://{host}{path}"

            resp = queue_request(method, url, headers, body)

            if resp:
                status = resp.get("status", 502)
                status_text = resp.get("statusText", "Relay")
                resp_headers = resp.get("headers", {})
                resp_body = resp.get("body", "")
                body_bytes = (resp_body.encode("utf-8", errors="replace")
                              if isinstance(resp_body, str) else resp_body)

                buf = f"HTTP/1.1 {status} {status_text}\r\n"
                for k, v in resp_headers.items():
                    if k.lower() in ("transfer-encoding", "content-length"):
                        continue
                    buf += f"{k}: {v}\r\n"
                buf += f"Content-Length: {len(body_bytes)}\r\n\r\n"
                tls.sendall(buf.encode() + body_bytes)
            else:
                tls.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n"
                            b"Content-Length: 0\r\n\r\n")

    # ── Plain HTTP proxy ─────────────────────────────────────────────────
    def _handle(self, method):
        cl = int(self.headers.get("Content-Length", 0))
        body = (self.rfile.read(cl).decode("utf-8", errors="replace")
                if cl else "")
        url = self.path
        headers = {k: self.headers[k] for k in self.headers}

        resp = queue_request(method, url, headers, body)

        if resp:
            status = resp.get("status", 502)
            self.send_response(status)
            resp_headers = resp.get("headers", {})
            resp_body = resp.get("body", "")
            body_bytes = (resp_body.encode("utf-8", errors="replace")
                          if isinstance(resp_body, str) else resp_body)

            for k, v in resp_headers.items():
                if k.lower() in ("transfer-encoding", "connection",
                                  "keep-alive", "content-length",
                                  "content-encoding"):
                    continue
                self.send_header(k, v)

            self.send_header("Content-Length", len(body_bytes))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body_bytes)
        else:
            self.send_error(504, "Browser relay timeout")

    def log_message(self, fmt, *args):
        pass


# ── Web / API server (browser connects here) ────────────────────────────────

class ApiHandler(BaseHTTPRequestHandler):
    """Serves the relay dashboard and JSON endpoints."""

    _ui_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "index.html")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._serve_ui()
        elif path == "/relay/pending":
            self._get_pending()
        elif path == "/relay/stats":
            self._json_response(relay_stats)
        elif path == "/scan/status":
            self._json_response({"status": scan_status})
        elif path == "/scan/log":
            offset = int(params.get("offset", ["0"])[0])
            self._get_scan_log(offset)
        elif path == "/scan/question":
            self._get_question()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/scan/start":
            self._start_scan()
        elif self.path == "/scan/stop":
            self._stop_scan()
        elif self.path == "/scan/answer":
            self._answer_question()
        elif self.path.startswith("/relay/response/"):
            req_id = self.path[len("/relay/response/"):]
            self._post_response(req_id)
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self._cors(200)
        self.end_headers()

    # ── helpers ──────────────────────────────────────────────────────────
    def _cors(self, code):
        self.send_response(code)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, obj, code=200):
        body = json.dumps(obj).encode()
        self._cors(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _serve_ui(self):
        try:
            with open(self._ui_path, "rb") as fh:
                content = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=UTF-8")
            self.send_header("Content-Length", len(content))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "index.html not found")

    def _get_pending(self):
        items = []
        with pending_lock:
            for rid, req in pending_requests.items():
                if not req["claimed"]:
                    items.append({
                        "id": rid,
                        "method": req["method"],
                        "url": req["url"],
                        "headers": req["headers"],
                        "body": req["body"],
                    })
                    req["claimed"] = True
        self._json_response(items)

    def _post_response(self, req_id):
        cl = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(cl)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            self._json_response({"ok": False, "error": "bad json"}, 400)
            return

        ok = False
        with pending_lock:
            if req_id in pending_requests:
                pending_requests[req_id]["response"] = data
                pending_requests[req_id]["event"].set()
                ok = True
        self._json_response({"ok": ok})

    def _start_scan(self):
        cl = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(cl)
        try:
            config = json.loads(raw)
        except json.JSONDecodeError:
            self._json_response({"ok": False, "message": "bad json"}, 400)
            return
        ok, msg = start_scan(config)
        self._json_response({"ok": ok, "message": msg})

    def _stop_scan(self):
        ok = stop_scan()
        self._json_response({"ok": ok})

    def _get_scan_log(self, offset):
        with scan_output_lock:
            lines = scan_output[offset:]
            total = len(scan_output)
        with question_lock:
            question = pending_question["text"] if pending_question else None
        self._json_response({
            "lines": lines,
            "total": total,
            "status": scan_status,
            "question": question,
        })

    def _get_question(self):
        with question_lock:
            q = pending_question["text"] if pending_question else None
        self._json_response({"question": q})

    def _answer_question(self):
        cl = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(cl)
        try:
            data = json.loads(raw)
            answer = data.get("answer", "").strip() + "\n"
        except json.JSONDecodeError:
            self._json_response({"ok": False, "error": "bad json"}, 400)
            return

        ok = False
        with question_lock:
            if pending_question and scan_process and scan_process.poll() is None:
                try:
                    # stdin is binary (bufsize=0), encode answer
                    scan_process.stdin.write(answer.encode("utf-8"))
                    scan_process.stdin.flush()
                    pending_question["event"].set()
                    ok = True
                except Exception as exc:
                    self._json_response({"ok": False, "error": str(exc)}, 500)
                    return

        self._json_response({"ok": ok})

    def log_message(self, fmt, *args):
        pass


# ── Threading wrappers ───────────────────────────────────────────────────────

class ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ── Stale-request cleanup ────────────────────────────────────────────────────

def cleanup_loop(interval=30, max_age=120):
    while True:
        time.sleep(interval)
        now = time.time()
        with pending_lock:
            stale = [rid for rid, r in pending_requests.items()
                     if now - r["time"] > max_age]
            for rid in stale:
                req = pending_requests.pop(rid)
                req["event"].set()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global PROXY_PORT

    parser = argparse.ArgumentParser(
        description="sqlmap Browser Relay – route sqlmap traffic through a "
                    "remote browser")
    parser.add_argument("--proxy-port", type=int, default=8888,
                        help="Port sqlmap connects to (default 8888)")
    parser.add_argument("--api-port", type=int, default=80,
                        help="Port the browser connects to (default 80, "
                             "may need sudo)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Listen address (default 0.0.0.0)")
    args = parser.parse_args()

    PROXY_PORT = args.proxy_port

    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║       sqlmap  Browser  Relay             ║")
    print("  ╚══════════════════════════════════════════╝")
    print()

    print("  [*] Generating relay CA …")
    init_certs()
    print()

    threading.Thread(target=cleanup_loop, daemon=True).start()

    try:
        proxy = ThreadedServer((args.host, args.proxy_port), ProxyHandler)
    except PermissionError:
        print(f"  [!] Permission denied for proxy port {args.proxy_port}.")
        print(f"      Try: sudo python3 sqlmap.py --web-relay")
        raise SystemExit(1)
    except OSError as exc:
        print(f"  [!] Cannot bind proxy port {args.proxy_port}: {exc}")
        raise SystemExit(1)

    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    try:
        api = ThreadedServer((args.host, args.api_port), ApiHandler)
    except PermissionError:
        print(f"  [!] Permission denied for port {args.api_port}.")
        print(f"      Try: sudo python3 sqlmap.py --web-relay")
        print(f"      Or use a higher port: python3 sqlmap.py --web-relay --api-port 8889")
        raise SystemExit(1)
    except OSError as exc:
        print(f"  [!] Cannot bind port {args.api_port}: {exc}")
        raise SystemExit(1)

    print(f"  [*] Proxy (internal) → 127.0.0.1:{args.proxy_port}")
    print(f"  [*] Web UI           → http://0.0.0.0:{args.api_port}/")
    print()
    print(f"  Open http://YOUR_MACBOOK_IP:{args.api_port}/ in the")
    print(f"  remote browser, fill in the target, and click Start.")
    print()
    print("  Waiting for requests …")
    print()

    try:
        api.serve_forever()
    except KeyboardInterrupt:
        print("\n  [*] Shutting down …")
        stop_scan()
        proxy.shutdown()
        api.shutdown()


if __name__ == "__main__":
    main()
