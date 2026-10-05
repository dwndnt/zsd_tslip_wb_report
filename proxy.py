import http.server
import select
import socket
import socketserver
import sys
import threading
import time
from urllib.parse import urlsplit


# ============================================================
# CONFIGURATION
# ============================================================

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8080

UPSTREAM_PROXY_HOST = "44.216.27.249"
UPSTREAM_PROXY_PORT = 3128

CONNECT_TIMEOUT = 15
UPSTREAM_RETRIES = 3
RETRY_DELAY = 1.0

SELECT_TIMEOUT = 1.0
IDLE_TIMEOUT = 300
BUFFER_SIZE = 64 * 1024

USER_AGENT = "Authorized-Pentest-Diagnostic-Relay/1.0"

YOUTUBE_DOMAINS = {
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "youtube-nocookie.com",
    "googleapis.com",
    "gstatic.com",
}


# ============================================================
# LOGGING
# ============================================================

def log(message):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}", flush=True)


# ============================================================
# SOCKET HELPERS
# ============================================================

def configure_socket(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    if sys.platform.startswith("linux"):
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
        except OSError:
            pass

    elif sys.platform.startswith("win"):
        try:
            sock.ioctl(
                socket.SIO_KEEPALIVE_VALS,
                (1, 60000, 15000)
            )
        except OSError:
            pass


def close_socket(sock):
    if sock is None:
        return

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

    try:
        sock.close()
    except OSError:
        pass


# ============================================================
# TLS DIAGNOSTICS
# ============================================================

def inspect_tls_record(data):
    """
    Inspect the beginning of a TLS record.

    This function ONLY observes the data.
    It does not modify, fragment, delay, or reorder anything.
    """

    if len(data) < 5:
        return None

    content_type = data[0]
    version = data[1:3]
    record_length = int.from_bytes(data[3:5], "big")

    return {
        "content_type": content_type,
        "version": version.hex(),
        "record_length": record_length,
        "received_bytes": len(data),
        "complete": len(data) >= 5 + record_length,
    }


def is_tls_client_hello(data):
    """
    Detect the beginning of a TLS Handshake record containing
    a ClientHello.

    TLS record:
        byte 0      = 0x16 (Handshake)
        byte 1..2   = TLS version
        byte 3..4   = record length
        byte 5      = 0x01 (ClientHello)
    """

    return (
        len(data) >= 6
        and data[0] == 0x16
        and data[1] == 0x03
        and data[5] == 0x01
    )


def log_tls_info(direction, data):
    info = inspect_tls_record(data)

    if not info:
        return

    log(
        f"[TLS {direction}] "
        f"type=0x{info['content_type']:02x} "
        f"version={info['version']} "
        f"record={info['record_length']} "
        f"received={info['received_bytes']} "
        f"complete={info['complete']}"
    )

    if is_tls_client_hello(data):
        log(
            f"[TLS {direction}] "
            f"ClientHello detected, first_packet_bytes={len(data)}"
        )


# ============================================================
# HOSTNAME CLASSIFICATION
# ============================================================

def is_youtube_target(host):
    """
    Strict hostname matching.

    Examples:
        youtube.com              -> True
        www.youtube.com          -> True
        m.youtube.com            -> True
        foo.googlevideo.com      -> True

        notyoutube.com           -> False
    """

    host = host.lower().rstrip(".")

    for domain in YOUTUBE_DOMAINS:
        if host == domain:
            return True

        if host.endswith("." + domain):
            return True

    return False


# ============================================================
# UPSTREAM PROXY
# ============================================================

def read_http_headers(sock, timeout=CONNECT_TIMEOUT):
    sock.settimeout(timeout)

    data = b""

    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)

        if not chunk:
            break

        data += chunk

        if len(data) > 64 * 1024:
            raise RuntimeError("HTTP response headers too large")

    return data


def connect_upstream(target_host, target_port):
    """
    Establish:

        local relay -> upstream HTTP proxy

    Then issue:

        CONNECT target_host:target_port HTTP/1.1
    """

    last_error = None

    for attempt in range(1, UPSTREAM_RETRIES + 1):
        upstream = None

        try:
            log(
                f"[UPSTREAM] Connecting "
                f"{UPSTREAM_PROXY_HOST}:{UPSTREAM_PROXY_PORT} "
                f"(attempt {attempt}/{UPSTREAM_RETRIES})"
            )

            upstream = socket.create_connection(
                (
                    UPSTREAM_PROXY_HOST,
                    UPSTREAM_PROXY_PORT,
                ),
                timeout=CONNECT_TIMEOUT,
            )

            configure_socket(upstream)

            request = (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Proxy-Connection: Keep-Alive\r\n"
                f"\r\n"
            ).encode("ascii")

            upstream.sendall(request)

            response = read_http_headers(upstream)

            first_line = response.split(b"\r\n", 1)[0]

            log(
                "[UPSTREAM] CONNECT response: "
                + first_line.decode("latin1", errors="replace")
            )

            if not response.startswith(b"HTTP/"):
                raise RuntimeError(
                    "Invalid HTTP response from upstream proxy"
                )

            try:
                status_code = int(
                    response.split(b" ", 2)[1]
                )
            except Exception:
                raise RuntimeError(
                    "Unable to parse upstream HTTP status"
                )

            if status_code != 200:
                raise RuntimeError(
                    f"Upstream CONNECT failed with HTTP {status_code}"
                )

            log(
                f"[UPSTREAM] Tunnel established "
                f"for {target_host}:{target_port}"
            )

            return upstream

        except Exception as exc:
            last_error = exc

            log(
                f"[UPSTREAM] Attempt {attempt} failed: "
                f"{type(exc).__name__}: {exc}"
            )

            close_socket(upstream)

            if attempt < UPSTREAM_RETRIES:
                time.sleep(RETRY_DELAY)

    raise RuntimeError(
        f"Unable to establish upstream tunnel: {last_error}"
    )


# ============================================================
# TCP RELAY
# ============================================================

def relay(client, upstream, target_host):
    """
    Transparent TCP relay.

    Important:
    - No TLS termination
    - No TLS modification
    - No packet fragmentation
    - No packet reordering
    - No ClientHello rewriting
    """

    sockets = [client, upstream]

    total_client_to_upstream = 0
    total_upstream_to_client = 0

    client_first_data = True
    upstream_first_data = True

    last_activity = time.monotonic()

    log(
        f"[RELAY] Starting tunnel "
        f"target={target_host}"
    )

    try:
        while True:

            if time.monotonic() - last_activity > IDLE_TIMEOUT:
                log(
                    f"[RELAY] Idle timeout "
                    f"target={target_host}"
                )
                break

            readable, _, exceptional = select.select(
                sockets,
                [],
                sockets,
                SELECT_TIMEOUT,
            )

            if exceptional:
                for sock in exceptional:
                    if sock is client:
                        log("[RELAY] Client socket exception")
                    elif sock is upstream:
                        log("[RELAY] Upstream socket exception")

                break

            if not readable:
                continue

            for sock in readable:

                try:
                    data = sock.recv(BUFFER_SIZE)

                except ConnectionResetError as exc:
                    if sock is client:
                        log(
                            "[RELAY] Client -> relay "
                            f"connection reset: {exc}"
                        )
                    else:
                        log(
                            "[RELAY] Upstream -> relay "
                            f"connection reset: {exc}"
                        )

                    return

                except OSError as exc:
                    if sock is client:
                        log(
                            "[RELAY] Client recv error: "
                            f"{type(exc).__name__}: {exc}"
                        )
                    else:
                        log(
                            "[RELAY] Upstream recv error: "
                            f"{type(exc).__name__}: {exc}"
                        )

                    return

                if not data:
                    if sock is client:
                        log(
                            "[RELAY] Client sent FIN "
                            "(clean close)"
                        )
                    else:
                        log(
                            "[RELAY] Upstream sent FIN "
                            "(clean close)"
                        )

                    return

                last_activity = time.monotonic()

                # ------------------------------------------------
                # CLIENT -> UPSTREAM
                # ------------------------------------------------

                if sock is client:

                    total_client_to_upstream += len(data)

                    if client_first_data:
                        client_first_data = False

                        log(
                            f"[RELAY] Client -> upstream "
                            f"first read={len(data)} bytes"
                        )

                        log_tls_info("C->U", data)

                    try:
                        upstream.sendall(data)

                    except BrokenPipeError as exc:
                        log(
                            "[RELAY] Upstream pipe closed "
                            f"while sending C->U: {exc}"
                        )
                        return

                    except ConnectionResetError as exc:
                        log(
                            "[RELAY] Upstream reset "
                            f"while sending C->U: {exc}"
                        )
                        return

                    except OSError as exc:
                        log(
                            "[RELAY] Upstream send error: "
                            f"{type(exc).__name__}: {exc}"
                        )
                        return

                # ------------------------------------------------
                # UPSTREAM -> CLIENT
                # ------------------------------------------------

                else:

                    total_upstream_to_client += len(data)

                    if upstream_first_data:
                        upstream_first_data = False

                        log(
                            f"[RELAY] Upstream -> client "
                            f"first read={len(data)} bytes"
                        )

                        log_tls_info("U->C", data)

                    try:
                        client.sendall(data)

                    except BrokenPipeError as exc:
                        log(
                            "[RELAY] Client pipe closed "
                            f"while sending U->C: {exc}"
                        )
                        return

                    except ConnectionResetError as exc:
                        log(
                            "[RELAY] Client reset "
                            f"while sending U->C: {exc}"
                        )
                        return

                    except OSError as exc:
                        log(
                            "[RELAY] Client send error: "
                            f"{type(exc).__name__}: {exc}"
                        )
                        return

    finally:
        log(
            f"[RELAY] Closed target={target_host} "
            f"C->U={total_client_to_upstream} bytes "
            f"U->C={total_upstream_to_client} bytes"
        )


# ============================================================
# CONNECT HANDLER
# ============================================================

class ProxyHandler(http.server.BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        log(
            "[HTTP] "
            + format % args
        )

    def do_CONNECT(self):

        target = self.path

        if ":" not in target:
            self.send_error(
                400,
                "CONNECT target must be host:port"
            )
            return

        target_host, target_port_text = target.rsplit(":", 1)

        try:
            target_port = int(target_port_text)
        except ValueError:
            self.send_error(
                400,
                "Invalid target port"
            )
            return

        target_host = target_host.strip().lower()

        log(
            f"[CLIENT] CONNECT "
            f"{target_host}:{target_port} "
            f"from {self.client_address[0]}:"
            f"{self.client_address[1]}"
        )

        log(
            f"[TARGET] YouTube classification="
            f"{is_youtube_target(target_host)}"
        )

        upstream = None

        try:
            upstream = connect_upstream(
                target_host,
                target_port,
            )

            self.send_response(200, "Connection Established")
            self.send_header(
                "Proxy-Agent",
                "Authorized-Pentest-Diagnostic-Relay/1.0"
            )
            self.end_headers()

            # Important:
            # Do not manipulate socket blocking state repeatedly.
            self.connection.setblocking(True)
            upstream.setblocking(True)

            relay(
                self.connection,
                upstream,
                target_host,
            )

        except Exception as exc:

            log(
                f"[CONNECT] Failed "
                f"{target_host}:{target_port}: "
                f"{type(exc).__name__}: {exc}"
            )

            try:
                self.send_error(
                    502,
                    f"Upstream proxy error: {exc}"
                )
            except Exception:
                pass

        finally:
            close_socket(upstream)

    # --------------------------------------------------------
    # Normal HTTP proxy requests
    # --------------------------------------------------------

    def do_GET(self):
        self.forward_http()

    def do_HEAD(self):
        self.forward_http()

    def do_POST(self):
        self.forward_http()

    def forward_http(self):

        url = self.path

        log(
            f"[HTTP] {self.command} {url}"
        )

        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https"):
            self.send_error(
                400,
                "Absolute HTTP/HTTPS URL required"
            )
            return

        if not parsed.hostname:
            self.send_error(
                400,
                "Invalid URL"
            )
            return

        host = parsed.hostname
        port = parsed.port

        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        # Normal HTTP proxying is intentionally limited
        # to HTTP here. HTTPS should use CONNECT.
        if parsed.scheme == "https":
            self.send_error(
                400,
                "Use CONNECT for HTTPS"
            )
            return

        try:

            upstream = socket.create_connection(
                (UPSTREAM_PROXY_HOST, UPSTREAM_PROXY_PORT),
                timeout=CONNECT_TIMEOUT,
            )

            configure_socket(upstream)

            request_headers = []

            for key, value in self.headers.items():

                # Avoid forwarding proxy-specific headers.
                if key.lower() in {
                    "proxy-connection",
                    "proxy-authorization",
                }:
                    continue

                request_headers.append(
                    f"{key}: {value}"
                )

            body = b""

            content_length = self.headers.get(
                "Content-Length"
            )

            if content_length:
                body = self.rfile.read(
                    int(content_length)
                )

            request_line = (
                f"{self.command} {url} HTTP/1.1\r\n"
            ).encode("latin1")

            headers = (
                "\r\n".join(request_headers)
                + "\r\n\r\n"
            ).encode("latin1")

            upstream.sendall(
                request_line +
                headers +
                body
            )

            while True:

                data = upstream.recv(
                    BUFFER_SIZE
                )

                if not data:
                    break

                self.wfile.write(data)
                self.wfile.flush()

        except Exception as exc:

            log(
                f"[HTTP] Forwarding failed: "
                f"{type(exc).__name__}: {exc}"
            )

            try:
                self.send_error(
                    502,
                    str(exc)
                )
            except Exception:
                pass

        finally:
            close_socket(
                locals().get("upstream")
            )


# ============================================================
# SERVER
# ============================================================

class ThreadingHTTPServer(
    socketserver.ThreadingMixIn,
    http.server.HTTPServer
):

    daemon_threads = True
    allow_reuse_address = True


def main():

    log("=" * 70)
    log("Authorized Pentest Diagnostic HTTP CONNECT Relay")
    log("=" * 70)

    log(
        f"Local proxy   : "
        f"http://{LOCAL_HOST}:{LOCAL_PORT}"
    )

    log(
        f"Upstream proxy: "
        f"{UPSTREAM_PROXY_HOST}:{UPSTREAM_PROXY_PORT}"
    )

    log(
        "TLS mode      : transparent / diagnostic"
    )

    log(
        "TLS mutation  : disabled"
    )

    log(
        "Fragmentation  : disabled"
    )

    log("=" * 70)

    server = ThreadingHTTPServer(
        (LOCAL_HOST, LOCAL_PORT),
        ProxyHandler,
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        log("Stopping proxy...")

    finally:
        server.server_close()
        log("Proxy stopped.")


if __name__ == "__main__":
    main()