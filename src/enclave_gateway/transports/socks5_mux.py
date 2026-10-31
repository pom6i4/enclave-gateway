"""RFC 1928 SOCKS5 Server & Bidirectional TCP Multiplexer over RdpVfsTransport."""

from __future__ import annotations

import queue
import socket
import struct
import threading
import time
import urllib.parse
from typing import BinaryIO, Callable

from enclave_gateway.config import PortForwardSpec
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, RdpVfsTunnelServer

SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF

SOCKS5_CMD_CONNECT = 0x01

SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04

SOCKS5_REP_SUCCEEDED = 0x00
SOCKS5_REP_GENERAL_FAILURE = 0x01
SOCKS5_REP_HOST_UNREACHABLE = 0x04
SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07
SOCKS5_REP_ATYP_NOT_SUPPORTED = 0x08


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise EOFError("Unexpected EOF during SOCKS5 handshake")
        buf.extend(chunk)
    return bytes(buf)


def build_socks5_reply(rep: int, bind_ip: str = "0.0.0.0", bind_port: int = 0) -> bytes:
    """Build a 10-byte RFC 1928 IPv4 SOCKS5 reply packet."""
    ip_bytes = socket.inet_aton(bind_ip)
    return struct.pack("!BBBB4sH", SOCKS5_VERSION, rep, 0x00, SOCKS5_ATYP_IPV4, ip_bytes, bind_port)


def _read_cstring(sock: socket.socket, max_len: int = 256) -> bytes:
    buf = bytearray()
    while len(buf) < max_len:
        ch = _recv_exact(sock, 1)
        if ch == b"\x00":
            break
        buf.extend(ch)
    return bytes(buf)


def negotiate_proxy_destination(
    conn: socket.socket,
    host_resolver: Callable[[str], str] | None = None,
) -> tuple[str, int, str, bytes]:
    """Auto-detect and negotiate SOCKS5, SOCKS4/4a, HTTP CONNECT, or HTTP Proxy on the same port."""
    first_b = _recv_exact(conn, 1)[0]

    # 1. RFC 1928 SOCKS5
    if first_b == SOCKS5_VERSION:
        nmethods = _recv_exact(conn, 1)[0]
        methods = _recv_exact(conn, nmethods)
        if SOCKS5_AUTH_NONE not in methods:
            conn.sendall(bytes([SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE]))
            raise PermissionError("Client does not support SOCKS5 no-auth (0x00)")

        conn.sendall(bytes([SOCKS5_VERSION, SOCKS5_AUTH_NONE]))

        req_hdr = _recv_exact(conn, 4)
        req_ver, cmd, _rsv, atyp = req_hdr[0], req_hdr[1], req_hdr[2], req_hdr[3]
        if req_ver != SOCKS5_VERSION:
            raise ValueError(f"Invalid SOCKS5 request version: {req_ver}")
        if cmd != SOCKS5_CMD_CONNECT:
            conn.sendall(build_socks5_reply(SOCKS5_REP_CMD_NOT_SUPPORTED))
            raise ValueError(f"Unsupported SOCKS5 command: {cmd} (only CONNECT=1 is supported)")

        if atyp == SOCKS5_ATYP_IPV4:
            raw_ip = _recv_exact(conn, 4)
            target_host = socket.inet_ntoa(raw_ip)
        elif atyp == SOCKS5_ATYP_DOMAIN:
            domain_len = _recv_exact(conn, 1)[0]
            target_host = _recv_exact(conn, domain_len).decode("utf-8", errors="replace")
        elif atyp == SOCKS5_ATYP_IPV6:
            raw_ip6 = _recv_exact(conn, 16)
            target_host = socket.inet_ntop(socket.AF_INET6, raw_ip6)
        else:
            conn.sendall(build_socks5_reply(SOCKS5_REP_ATYP_NOT_SUPPORTED))
            raise ValueError(f"Unsupported SOCKS5 address type: {atyp}")

        port_bytes = _recv_exact(conn, 2)
        target_port = struct.unpack("!H", port_bytes)[0]
        if host_resolver is not None:
            target_host = host_resolver(target_host)
        return target_host, target_port, "socks5", b""

    # 2. SOCKS4 / SOCKS4a
    if first_b == 0x04:
        rest = _recv_exact(conn, 7)
        cmd = rest[0]
        if cmd != 0x01:
            conn.sendall(struct.pack("!BBH4s", 0x00, 0x5B, 0, b"\x00\x00\x00\x00"))
            raise ValueError(f"Unsupported SOCKS4 command: {cmd}")
        target_port = struct.unpack("!H", rest[1:3])[0]
        raw_ip = rest[3:7]
        _read_cstring(conn)  # userid
        if raw_ip[:3] == b"\x00\x00\x00" and raw_ip[3] != 0:
            target_host = _read_cstring(conn).decode("utf-8", errors="replace")
        else:
            target_host = socket.inet_ntoa(raw_ip)
        if host_resolver is not None:
            target_host = host_resolver(target_host)
        return target_host, target_port, "socks4", b""

    # 3. HTTP CONNECT or plain HTTP Proxy
    if chr(first_b) in ("C", "G", "P", "H", "D", "O"):
        buf = bytearray([first_b])
        while b"\r\n\r\n" not in buf and len(buf) < 32768:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        raw_req = bytes(buf)
        hdr_part, sep, body_rem = raw_req.partition(b"\r\n\r\n")
        if not sep:
            raise ValueError("Malformed HTTP proxy request header")
        lines = hdr_part.decode("utf-8", errors="replace").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) < 3:
            raise ValueError(f"Invalid HTTP request line: {lines[0]}")
        method, target_uri, http_ver = parts[0], parts[1], parts[2]
        if method.upper() == "CONNECT":
            host_part, _, port_part = target_uri.rpartition(":")
            target_host = (host_part or target_uri).strip("[]")
            target_port = int(port_part) if port_part.isdigit() else 443
            if host_resolver is not None:
                target_host = host_resolver(target_host)
            return target_host, target_port, "http_connect", body_rem

        parsed = urllib.parse.urlsplit(target_uri)
        target_host = parsed.hostname or ""
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        rel_path = parsed.path or "/"
        if parsed.query:
            rel_path += f"?{parsed.query}"
        lines[0] = f"{method} {rel_path} {http_ver}"
        rewritten = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body_rem
        if host_resolver is not None and target_host:
            target_host = host_resolver(target_host)
        return target_host, target_port, "http_proxy", rewritten

    raise ValueError(f"Unsupported proxy protocol byte: {first_b}")


def negotiate_socks5_destination(
    conn: socket.socket,
    host_resolver: Callable[[str], str] | None = None,
) -> tuple[str, int]:
    """Perform RFC 1928 SOCKS5 method negotiation and parse the CONNECT target."""
    host, port, _proto, _init = negotiate_proxy_destination(
        conn, host_resolver=host_resolver
    )
    return host, port


class Socks5VfsServer:
    """Bidirectional SOCKS5 proxy server that multiplexes TCP streams over RdpVfsTransport."""

    def __init__(
        self,
        transport: RdpVfsTransport,
        bind_host: str = "127.0.0.1",
        bind_port: int = 1080,
        *,
        target_aliases: dict[str, str] | None = None,
    ) -> None:
        self.transport = transport
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.target_aliases = dict(target_aliases or {})
        self._stop_event = threading.Event()
        self._server_socket: socket.socket | None = None
        self._lock = threading.Lock()
        self._active_connections = 0

    @property
    def active_connections(self) -> int:
        with self._lock:
            return self._active_connections

    def resolve_host(self, host: str) -> str:
        return self.target_aliases.get(host, host)

    def serve_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind_host, self.bind_port))
        self.bind_port = srv.getsockname()[1]
        srv.listen(32)
        srv.settimeout(0.5)
        self._server_socket = srv
        try:
            while not self._stop_event.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                threading.Thread(
                    target=self._handle_socks5_client, args=(conn,), daemon=True
                ).start()
        finally:
            srv.close()

    def stop(self) -> None:
        self._stop_event.set()

    def _handle_socks5_client(self, conn: socket.socket) -> None:
        conn.settimeout(10.0)
        with self._lock:
            self._active_connections += 1
        proto = "socks5"
        try:
            target_host, target_port, proto, initial_tx = negotiate_proxy_destination(
                conn, host_resolver=self.resolve_host
            )
            conn_id = self.transport.mux_open(target_host, target_port)
            try:
                if proto == "socks5":
                    conn.sendall(build_socks5_reply(SOCKS5_REP_SUCCEEDED))
                elif proto == "socks4":
                    conn.sendall(struct.pack("!BBH4s", 0x00, 0x5A, 0, b"\x00\x00\x00\x00"))
                elif proto == "http_connect":
                    conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                pending_tx = initial_tx
                idle_streak = 0
                while not self._stop_event.is_set():
                    recv_wait = 0.025 if idle_streak < 8 else min(0.25, 0.025 * (idle_streak - 5))
                    conn.settimeout(recv_wait)
                    tx_chunks: list[bytes] = []
                    if pending_tx:
                        tx_chunks.append(pending_tx)
                        pending_tx = b""
                    client_eof = False
                    try:
                        data = conn.recv(65536)
                        if data == b"":
                            client_eof = True
                        elif data:
                            tx_chunks.append(data)
                    except (socket.timeout, BlockingIOError):
                        pass
                    except OSError:
                        client_eof = True

                    tx_payload = b"".join(tx_chunks)
                    rx_bytes, remote_eof = self.transport.mux_io(
                        conn_id,
                        tx_payload,
                        read_wait_ms=35 if tx_payload else (80 if idle_streak < 8 else 150),
                    )
                    if tx_payload or rx_bytes:
                        idle_streak = 0
                    else:
                        idle_streak += 1

                    if rx_bytes:
                        conn.settimeout(5.0)
                        conn.sendall(rx_bytes)

                    if remote_eof or client_eof:
                        break
            finally:
                try:
                    self.transport.mux_close(conn_id)
                except Exception:
                    pass
        except ConnectionError:
            try:
                if proto == "socks5":
                    conn.sendall(build_socks5_reply(SOCKS5_REP_HOST_UNREACHABLE))
                elif proto in ("http_connect", "http_proxy"):
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
        except Exception:
            try:
                if proto == "socks5":
                    conn.sendall(build_socks5_reply(SOCKS5_REP_GENERAL_FAILURE))
            except Exception:
                pass
        finally:
            with self._lock:
                self._active_connections -= 1
            conn.close()


def pump_stdio_mux(
    transport: RdpVfsTransport,
    target_host: str,
    target_port: int,
    stdin_stream: BinaryIO,
    stdout_stream: BinaryIO,
    *,
    stop_event: threading.Event | None = None,
) -> int:
    """Bridge binary stdin/stdout with a persistent multiplexed TCP connection (OpenSSH ProxyCommand)."""
    conn_id = transport.mux_open(target_host, target_port)
    in_queue: queue.Queue[bytes | None] = queue.Queue()

    def _stdin_reader() -> None:
        try:
            read_fn = getattr(stdin_stream, "read1", None) or stdin_stream.read
            while True:
                chunk = read_fn(65536)
                if not chunk:
                    in_queue.put(None)
                    break
                in_queue.put(chunk)
        except Exception:
            in_queue.put(None)

    reader_thread = threading.Thread(target=_stdin_reader, daemon=True)
    reader_thread.start()

    stdin_eof = False
    try:
        while stop_event is None or not stop_event.is_set():
            tx_chunks: list[bytes] = []
            if not stdin_eof:
                try:
                    item = in_queue.get(timeout=0.02)
                    if item is None:
                        stdin_eof = True
                    else:
                        tx_chunks.append(item)
                        while True:
                            try:
                                more = in_queue.get_nowait()
                                if more is None:
                                    stdin_eof = True
                                    break
                                tx_chunks.append(more)
                            except queue.Empty:
                                break
                except queue.Empty:
                    pass

            tx_payload = b"".join(tx_chunks)
            rx_bytes, remote_eof = transport.mux_io(
                conn_id,
                tx_payload,
                read_wait_ms=40 if tx_payload else 80,
            )
            if rx_bytes:
                stdout_stream.write(rx_bytes)
                stdout_stream.flush()

            if remote_eof or (stdin_eof and not rx_bytes):
                break
        return 0
    finally:
        try:
            transport.mux_close(conn_id)
        except Exception:
            pass


class MultiPortForwardSupervisor:
    """Concurrently runs multiple RdpVfsTunnelServer port forwards and an optional Socks5VfsServer."""

    def __init__(
        self,
        transport: RdpVfsTransport,
        forwards: dict[str, PortForwardSpec],
        *,
        socks5_port: int | None = None,
        socks5_bind: str = "127.0.0.1",
        target_aliases: dict[str, str] | None = None,
    ) -> None:
        self.transport = transport
        self.forwards = dict(forwards)
        self.tunnel_servers: dict[str, RdpVfsTunnelServer] = {}
        for name, spec in self.forwards.items():
            self.tunnel_servers[name] = RdpVfsTunnelServer(
                transport,
                spec.local_port,
                spec.target_host,
                spec.target_port,
                multiplexed=True,
            )
        self.socks5_server: Socks5VfsServer | None = None
        if socks5_port is not None:
            self.socks5_server = Socks5VfsServer(
                transport,
                bind_host=socks5_bind,
                bind_port=socks5_port,
                target_aliases=target_aliases,
            )
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()

    def start(self) -> None:
        for name, srv in self.tunnel_servers.items():
            t = threading.Thread(
                target=srv.serve_forever, name=f"egw-fwd-{name}", daemon=True
            )
            t.start()
            self._threads.append(t)
        if self.socks5_server is not None:
            t_socks = threading.Thread(
                target=self.socks5_server.serve_forever,
                name="egw-socks5",
                daemon=True,
            )
            t_socks.start()
            self._threads.append(t_socks)

    def serve_forever(self) -> None:
        self.start()
        try:
            while not self._stop_event.is_set():
                time.sleep(0.25)
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        for srv in self.tunnel_servers.values():
            srv.stop()
        if self.socks5_server is not None:
            self.socks5_server.stop()
