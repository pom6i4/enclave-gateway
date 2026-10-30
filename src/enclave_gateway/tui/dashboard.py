"""Interactive TUI dashboard (egw top) for live monitoring of Host -> Appliance -> Bastion -> TargetNodes."""

from __future__ import annotations

import curses
import sys
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from enclave_gateway.engine import EnclaveEngine


def _box_line(text: str, width: int) -> str:
    inner = width - 4
    clipped = text[:inner].ljust(inner)
    return f"│ {clipped} │"


def render_dashboard_text(
    engine: EnclaveEngine,
    *,
    status_override: dict[str, Any] | None = None,
    audit_limit: int = 8,
    width: int = 92,
    banner_msg: str = "",
) -> str:
    """Render a full text snapshot of the Enclave Gateway topology and Flight Recorder."""
    st = status_override if status_override is not None else engine.status()
    cfg = engine.config
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    app_st = st.get("appliance") or {}
    prov_st = st.get("provider") or {}
    bast_st = st.get("bastion") or {}
    w_state = bast_st.get("worker_state") or {}

    vm_up = bool(app_st.get("running")) or app_st.get("hypervisor") == "direct"
    tun_up = bool(prov_st.get("tunnel_up"))
    wrk_up = bool(bast_st.get("worker_healthy"))

    app_badge = "[ONLINE]" if vm_up else "[OFFLINE]"
    tun_badge = "[TUNNEL UP]" if tun_up else "[TUNNEL DOWN]"
    wrk_badge = "[WORKER HEALTHY]" if wrk_up else "[WORKER STALE]"

    top_border = "┌" + "─" * (width - 2) + "┐"
    sep_border = "├" + "─" * (width - 2) + "┤"
    bot_border = "└" + "─" * (width - 2) + "┘"

    lines: list[str] = [
        top_border,
        _box_line(
            f"ENCLAVE GATEWAY TUI MONITOR (egw top)   Profile: {st.get('profile', 'default')}   {now_utc}",
            width,
        ),
        _box_line(
            f"Chain: Host ──> Appliance {app_badge} ──> VPN {tun_badge} ──> Bastion {wrk_badge} ──> Targets ({len(cfg.targets)})",
            width,
        ),
        sep_border,
        _box_line("1. CRYPTOGRAPHIC APPLIANCE (@appliance)", width),
        _box_line(
            f"   Name: {app_st.get('name', cfg.appliance.name)}   State: {app_badge}   PID: {app_st.get('pid') or '-'}   Hypervisor: {app_st.get('hypervisor', cfg.appliance.hypervisor)}",
            width,
        ),
        _box_line(
            f"   MTU: {cfg.appliance.mtu}   SOCKS5 Port: 127.0.0.1:{cfg.appliance.socks5_port}   RDP Forward: 127.0.0.1:{cfg.appliance.rdp_forward_port}   Snapshot: {cfg.appliance.golden_snapshot}",
            width,
        ),
        sep_border,
        _box_line("2. VPN CRYPTO PROVIDER", width),
        _box_line(
            f"   Provider: {prov_st.get('type', cfg.provider.type)}   Status: {tun_badge}   Source IP: {prov_st.get('source_ip') or '-'}   Probe: {prov_st.get('probe_host')}:{prov_st.get('probe_port')}",
            width,
        ),
    ]
    details = str(prov_st.get("details") or "").strip().replace("\n", " | ")
    if details:
        lines.append(_box_line(f"   Details: {details}", width))

    lines.extend(
        [
            sep_border,
            _box_line("3. BASTION RDP VFS RELAY (@bastion)", width),
            _box_line(
                f"   Bastion: {bast_st.get('host', cfg.bastion.host)}:{cfg.bastion.port}   Transport: {cfg.bastion.transport} ([MS-RDPEFS])   State: {wrk_badge}",
                width,
            ),
            _box_line(
                f"   Worker PID: {w_state.get('pid', '-')}   Uptime: {w_state.get('uptime_sec', '-')}s   Parallel Streams: {w_state.get('parallel_streams', cfg.bastion.parallel_streams)}   Active Mux: {w_state.get('active_mux_streams', 0)}",
                width,
            ),
            sep_border,
            _box_line("4. UPSTREAM TARGET NODES", width),
        ]
    )

    if not cfg.targets:
        lines.append(_box_line("   (no target nodes configured)", width))
    else:
        for t_name, t_spec in cfg.targets.items():
            lines.append(
                _box_line(
                    f"   • {t_name:<12} {t_spec.user}@{t_spec.host}:{t_spec.port:<6} via @{t_spec.via}",
                    width,
                )
            )

    lines.extend(
        [
            sep_border,
            _box_line("5. FLIGHT RECORDER (RECENT OPERATIONS)", width),
        ]
    )

    recent = engine.recorder.read_recent(limit=audit_limit)
    if not recent:
        lines.append(_box_line("   (no audit records yet)", width))
    else:
        for rec in reversed(recent):
            ts = str(rec.get("timestamp_utc", ""))[-9:-1]
            actor = str(rec.get("actor", "cli"))[:5]
            node = str(rec.get("node", ""))[:10]
            op = str(rec.get("operation", ""))[:14]
            code = int(rec.get("exit_code", 0))
            dur = int(rec.get("duration_ms", 0))
            summary = str(rec.get("summary", "")).replace("\n", " ")
            lines.append(
                _box_line(
                    f"   {ts} [{actor:<4}] {node:<10} {op:<14} exit={code:<3} {dur:>5}ms  {summary}",
                    width,
                )
            )

    lines.append(sep_border)
    if banner_msg:
        lines.append(_box_line(f"STATUS: {banner_msg}", width))
    lines.append(
        _box_line("Keys: [q] Quit   [r] Refresh Telemetry   [h] Self-Heal Chain (MTU + RDP)", width)
    )
    lines.append(bot_border)
    return "\n".join(lines)


def run_interactive_top(
    engine: EnclaveEngine,
    *,
    interval_sec: float = 2.0,
    once: bool = False,
) -> int:
    """Run the TUI dashboard either once (snapshot mode) or interactively via curses."""
    if once or not sys.stdout.isatty():
        print(render_dashboard_text(engine))
        return 0

    def _curses_loop(stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(200)
        last_refresh = 0.0
        cached_status: dict[str, Any] | None = None
        banner = ""

        while True:
            now = time.monotonic()
            if cached_status is None or (now - last_refresh) >= interval_sec:
                cached_status = engine.status()
                last_refresh = now

            max_y, max_x = stdscr.getmaxyx()
            render_width = max(60, min(110, max_x - 1))
            frame = render_dashboard_text(
                engine,
                status_override=cached_status,
                width=render_width,
                banner_msg=banner,
            )
            stdscr.erase()
            for row_idx, line in enumerate(frame.splitlines()):
                if row_idx >= max_y - 1:
                    break
                try:
                    stdscr.addstr(row_idx, 0, line[: max_x - 1])
                except curses.error:
                    pass
            stdscr.refresh()

            ch = stdscr.getch()
            if ch in (ord("q"), ord("Q"), 27):
                break
            if ch in (ord("r"), ord("R")):
                banner = "Refreshing telemetry..."
                cached_status = None
            elif ch in (ord("h"), ord("H")):
                banner = "Executing self-heal (MTU=1350 + RDP policy + Bastion reconnect)..."
                stdscr.refresh()
                res = engine.heal(actor="tui")
                banner = f"Self-heal completed (exit={res.exit_code}, {res.duration_ms}ms)"
                cached_status = None

    try:
        curses.wrapper(_curses_loop)
    except KeyboardInterrupt:
        pass
    except curses.error:
        print(render_dashboard_text(engine))
    return 0
