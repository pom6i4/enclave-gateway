"""RFC 1928 SOCKS5 Server & Bidirectional TCP Multiplexer over RdpVfsTransport."""

from __future__ import annotations

import socket
import struct
import threading
from typing import Callable

from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, pump_multiplexed_socket

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


def negotiate_socks5_destination(
    conn: socket.socket,
    host_resolver: Callable[[str], str] | None = None,
) -> tuple[str, int]:
    """Perform RFC 1928 SOCKS5 method negotiation and parse the CONNECT target."""
    hdr = _recv_exact(conn, 2)
    ver, nmethods = hdr[0], hdr[1]
    if ver != SOCKS5_VERSION:
        raise ValueError(f"Unsupported SOCKS version: {ver}")
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

    return target_host, target_port


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
        try:
            target_host, target_port = negotiate_socks5_destination(
                conn, host_resolver=self.resolve_host
            )
            conn_id = self.transport.mux_open(target_host, target_port)
            try:
                conn.sendall(build_socks5_reply(SOCKS5_REP_SUCCEEDED))
                conn.settimeout(0.03)
                while not self._stop_event.is_set():
                    tx_chunks: list[bytes] = []
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
                        read_wait_ms=40 if tx_payload else 100,
                    )
                    if rx_bytes:
                        conn.settimeout(5.0)
                        conn.sendall(rx_bytes)
                        conn.settimeout(0.03)

                    if remote_eof or client_eof:
                        break
            finally:
                try:
                    self.transport.mux_close(conn_id)
                except Exception:
                    pass
        except ConnectionError:
            try:
                conn.sendall(build_socks5_reply(SOCKS5_REP_HOST_UNREACHABLE))
            except Exception:
                pass
        except Exception:
            try:
                conn.sendall(build_socks5_reply(SOCKS5_REP_GENERAL_FAILURE))
            except Exception:
                pass
        finally:
            with self._lock:
                self._active_connections -= 1
            conn.close()
