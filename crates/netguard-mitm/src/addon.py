"""NetGuard mitmproxy addon.

Captures each HTTP/HTTPS flow and writes one JSON line per completed flow
to the Unix socket specified by the NETGUARD_SOCK environment variable.

Reopens the socket on disconnect so the daemon can restart independently.
"""

import json
import os
import socket
import threading
import time

SOCKET_PATH = os.environ.get("NETGUARD_SOCK", "/run/netguard/mitm.sock")
MAX_BODY = int(os.environ.get("NETGUARD_MAX_BODY", str(1024 * 1024)))

_sock_lock = threading.Lock()
_sock = None


def _connect():
    global _sock
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(SOCKET_PATH)
        _sock = s
    except (FileNotFoundError, ConnectionRefusedError, OSError):
        _sock = None


def _write_line(line: bytes):
    global _sock
    with _sock_lock:
        for _ in range(2):
            if _sock is None:
                _connect()
                if _sock is None:
                    return
            try:
                _sock.sendall(line)
                return
            except OSError:
                try:
                    _sock.close()
                except OSError:
                    pass
                _sock = None


def _body_to_str(raw: bytes) -> str:
    if not raw:
        return ""
    if len(raw) > MAX_BODY:
        raw = raw[:MAX_BODY]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()


def _headers_to_str(headers) -> str:
    out = []
    for k, v in headers.items(multi=True):
        out.append(f"{k}: {v}")
    return "\n".join(out)


def response(flow):
    try:
        req = flow.request
        resp = flow.response
        client = flow.client_conn.peername or ("0.0.0.0", 0)
        server = flow.server_conn.peername or ("0.0.0.0", 0)

        record = {
            "flow_id": flow.id,
            "client_ip": client[0],
            "client_port": client[1],
            "server_ip": server[0],
            "server_port": server[1],
            "method": req.method,
            "url": req.pretty_url,
            "request_headers": _headers_to_str(req.headers),
            "request_body": _body_to_str(req.get_content(strict=False) or b""),
            "status_code": resp.status_code if resp else 0,
            "response_headers": _headers_to_str(resp.headers) if resp else "",
            "response_body": _body_to_str(resp.get_content(strict=False) or b"") if resp else "",
            "started_at": time.time(),
        }
        _write_line((json.dumps(record) + "\n").encode("utf-8"))
    except Exception:
        # Never let addon errors kill mitmproxy
        pass
