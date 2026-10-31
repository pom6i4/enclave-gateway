"""Bounded TCP listener lifecycle with observable startup and connection cleanup."""

from __future__ import annotations

import socket
import threading


class TcpListener:
    def _init_listener(self, bind_host: str, port_attribute: str, max_clients: int = 128) -> None:
        self.bind_host = bind_host
        self._port_attribute = port_attribute
        self._stop_event = threading.Event()
        self.ready = threading.Event()
        self.start_error: Exception | None = None
        self._server_socket = None
        self._clients: set[socket.socket] = set()
        self._clients_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_clients)

    def serve_forever(self) -> None:
        try:
            family = socket.AF_INET6 if ":" in self.bind_host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((self.bind_host, getattr(self, self._port_attribute)))
                server.listen(32)
                server.settimeout(0.2)
                setattr(self, self._port_attribute, server.getsockname()[1])
                self._server_socket = server
                self.ready.set()
                while not self._stop_event.is_set():
                    try:
                        client, _ = server.accept()
                    except socket.timeout:
                        continue
                    if not self._slots.acquire(blocking=False):
                        client.close()
                        continue
                    with self._clients_lock:
                        self._clients.add(client)
                    threading.Thread(target=self._run_client, args=(client,), daemon=True).start()
        except Exception as exc:
            self.start_error = exc
            self.ready.set()
        finally:
            self.stop()

    def _run_client(self, client: socket.socket) -> None:
        try:
            self._handle_client(client)
        finally:
            with self._clients_lock:
                self._clients.discard(client)
            client.close()
            self._slots.release()

    def wait_ready(self, timeout: float = 3.0) -> None:
        if not self.ready.wait(timeout):
            self.stop()
            raise TimeoutError("TCP listener did not start")
        if self.start_error:
            raise OSError(f"TCP listener could not start: {self.start_error}") from self.start_error

    def stop(self) -> None:
        self._stop_event.set()
        with self._clients_lock:
            for client in self._clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
