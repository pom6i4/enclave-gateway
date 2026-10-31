"""RFC 1928 SOCKS5 Server & Bidirectional TCP Multiplexer over RdpVfsTransport."""

from __future__ import annotations

import queue
import re
import socket
import struct
import threading
import time
import urllib.parse
from typing import BinaryIO, Callable

from enclave_gateway.config import PortForwardSpec
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, RdpVfsTunnelServer, pump_mux_connection
from enclave_gateway.transports.listener import TcpListener

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
            return bytes(buf)
        buf.extend(ch)
    raise ValueError("SOCKS4 string is too long or unterminated")


def negotiate_proxy_destination(
    conn: socket.socket,
    host_resolver: Callable[[str], str] | None = None,
) -> tuple[str, int, str, bytes]:
    """Auto-detect and negotiate SOCKS5, SOCKS4/4a, HTTP CONNECT, or HTTP Proxy on the same port."""
    connection = conn
    deadline = time.monotonic() + 10.0

    class HandshakeConnection:
        def recv(self, count):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Proxy handshake deadline expired")
            setter = getattr(connection, "settimeout", None)
            if setter is not None:
                setter(remaining)
            return connection.recv(count)

        def sendall(self, data):
            connection.sendall(data)

    conn = HandshakeConnection()
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
        if _rsv != 0:
            conn.sendall(build_socks5_reply(SOCKS5_REP_GENERAL_FAILURE))
            raise ValueError("Invalid SOCKS5 reserved byte")
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
            if domain_len == 0:
                raise ValueError("Empty SOCKS5 domain")
            target_host = _recv_exact(conn, domain_len).decode("ascii")
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
    if 65 <= first_b <= 90:
        buf = bytearray([first_b])
        while b"\r\n\r\n" not in buf and len(buf) < 32768:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        raw_req = bytes(buf)
        hdr_part, sep, body_rem = raw_req.partition(b"\r\n\r\n")
        if not sep or len(hdr_part) + 4 > 32768:
            raise ValueError("Malformed HTTP proxy request header")
        lines = hdr_part.decode("iso-8859-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1") or not re.fullmatch(r"[A-Z-]+", parts[0]):
            raise ValueError(f"Invalid HTTP request line: {lines[0]}")
        method, target_uri, http_ver = parts[0], parts[1], parts[2]
        if method.upper() == "CONNECT":
            authority = urllib.parse.urlsplit("//" + target_uri)
            if (not authority.hostname or authority.username is not None or authority.path
                    or authority.query or authority.fragment or authority.port is None):
                raise ValueError("CONNECT requires host:port authority")
            target_host = authority.hostname
            target_port = authority.port
            if not 1 <= target_port <= 65535:
                raise ValueError("Invalid CONNECT port")
            if host_resolver is not None:
                target_host = host_resolver(target_host)
            return target_host, target_port, "http_connect", body_rem

        parsed = urllib.parse.urlsplit(target_uri)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username is not None or parsed.fragment:
            raise ValueError("HTTP proxy requires an absolute http URI; use CONNECT for TLS")
        target_host = parsed.hostname
        target_port = parsed.port or 80
        rel_path = parsed.path or "/"
        if parsed.query:
            rel_path += f"?{parsed.query}"
        headers = []
        for line in lines[1:]:
            key, colon, value = line.partition(":")
            if not colon or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                raise ValueError("Malformed HTTP header")
            headers.append((key, value.strip()))
        connection_tokens = {token.strip().lower() for k, v in headers if k.lower() == "connection" for token in v.split(",")}
        lengths = [v for k, v in headers if k.lower() == "content-length"]
        encodings = [v for k, v in headers if k.lower() == "transfer-encoding"]
        if (len(lengths) > 1 or len(encodings) > 1 or (lengths and encodings)
                or (lengths and not lengths[0].isdigit())
                or (encodings and encodings[0].lower() != "chunked")
                or connection_tokens & {"content-length", "transfer-encoding", "host"}):
            raise ValueError("Ambiguous HTTP message framing")
        excluded = connection_tokens | {"host", "connection", "proxy-authorization", "proxy-connection", "keep-alive", "upgrade"}
        authority = f"[{target_host}]" if ":" in target_host else target_host
        if parsed.port is not None:
            authority += f":{target_port}"
        outgoing = [f"{method} {rel_path} {http_ver}", f"Host: {authority}"]
        outgoing.extend(f"{k}: {v}" for k, v in headers if k.lower() not in excluded)
        # This connection carries one origin request; persistent proxy reuse would
        # require parsing and rewriting every subsequent request and response.
        outgoing.append("Connection: close")
        rewritten = ("\r\n".join(outgoing) + "\r\n\r\n").encode("iso-8859-1") + body_rem
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


class Socks5VfsServer(TcpListener):
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
        self._init_listener(bind_host, "bind_port")
        self._lock = threading.Lock()
        self._active_connections = 0

    @property
    def active_connections(self) -> int:
        with self._lock:
            return self._active_connections

    def resolve_host(self, host: str) -> str:
        return self.target_aliases.get(host, host)

    def _handle_client(self, conn: socket.socket) -> None:
        self._handle_socks5_client(conn)

    def _handle_socks5_client(self, conn: socket.socket) -> None:
        conn.settimeout(10.0)
        with self._lock:
            self._active_connections += 1
        proto = "socks5"
        established = False
        negotiated = False
        try:
            target_host, target_port, proto, initial_tx = negotiate_proxy_destination(
                conn, host_resolver=self.resolve_host
            )
            negotiated = True
            conn_id = self.transport.mux_open(target_host, target_port)
            try:
                if proto == "socks5":
                    conn.sendall(build_socks5_reply(SOCKS5_REP_SUCCEEDED))
                elif proto == "socks4":
                    conn.sendall(struct.pack("!BBH4s", 0x00, 0x5A, 0, b"\x00\x00\x00\x00"))
                elif proto == "http_connect":
                    conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                established = True
                pump_mux_connection(self.transport, conn, conn_id, stop_event=self._stop_event, initial_tx=initial_tx)
            finally:
                if not established:
                    try:
                        self.transport.mux_close(conn_id)
                    except Exception:
                        pass
        except ConnectionError:
            try:
                if proto == "socks5" and negotiated and not established:
                    conn.sendall(build_socks5_reply(SOCKS5_REP_HOST_UNREACHABLE))
                elif proto == "socks4" and not established:
                    conn.sendall(struct.pack("!BBH4s", 0, 0x5B, 0, b"\0" * 4))
                elif proto in ("http_connect", "http_proxy") and not established:
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception:
                pass
        except Exception:
            try:
                if proto == "socks5" and negotiated and not established:
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
    in_queue: queue.Queue[bytes | None] = queue.Queue(maxsize=16)
    reader_stop = threading.Event()

    def enqueue(item):
        while not reader_stop.is_set():
            try:
                in_queue.put(item, timeout=0.1)
                return
            except queue.Full:
                pass

    def _stdin_reader() -> None:
        try:
            read_fn = getattr(stdin_stream, "read1", None) or stdin_stream.read
            while True:
                chunk = read_fn(65536)
                if not chunk:
                    enqueue(None)
                    break
                enqueue(chunk)
        except Exception:
            enqueue(None)

    reader_thread = threading.Thread(target=_stdin_reader, daemon=True)
    reader_thread.start()

    stdin_eof = False
    write_shutdown = False
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
                        for _ in range(15):
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

            if stdin_eof and not write_shutdown:
                transport.mux_shutdown_write(conn_id)
                write_shutdown = True
            if remote_eof:
                break
        return 0
    finally:
        reader_stop.set()
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
                bind_host=spec.bind_host,
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
            try:
                srv.wait_ready()
            except Exception:
                self.stop()
                raise
        if self.socks5_server is not None:
            t_socks = threading.Thread(
                target=self.socks5_server.serve_forever,
                name="egw-socks5",
                daemon=True,
            )
            t_socks.start()
            self._threads.append(t_socks)
            try:
                self.socks5_server.wait_ready()
            except Exception:
                self.stop()
                raise

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
