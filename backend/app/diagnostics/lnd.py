"""LND connectivity diagnostics for support workflows.

This module is intentionally read-only. It prints environment wiring, mounted
file presence, certificate names, TLS readiness, and RPC permission checks
without dumping macaroon contents.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import ssl
from pathlib import Path
from typing import Any

import grpc

from backend.app.ln_client import LNClient
from backend.app.macaroon_store import MacaroonStore

DEFAULT_TIMEOUT_SECONDS = 6.0
DEFAULT_TEST_NAMES = ("localhost", "lnd", "lightning", "umbrel.local")


def stat_path(path: Path) -> str:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return "missing"
    except PermissionError:
        return "permission denied"
    except OSError as exc:
        return f"error: {exc}"
    return f"exists size={stat.st_size} mode={oct(stat.st_mode & 0o777)}"


def add_unique(values: list[str], value: str | None) -> None:
    if not value:
        return
    candidate = value.strip()
    if candidate and candidate not in values:
        values.append(candidate)


def cert_names(decoded: dict[str, Any]) -> tuple[list[str], list[str]]:
    dns_names: list[str] = []
    ip_names: list[str] = []
    for kind, value in decoded.get("subjectAltName", []) or []:
        if kind == "DNS":
            add_unique(dns_names, value)
        elif kind == "IP Address":
            add_unique(ip_names, value)
    for subject_group in decoded.get("subject", []) or []:
        for key, value in subject_group:
            if key == "commonName":
                add_unique(dns_names, value)
    return dns_names, ip_names


def channel_options(server_name: str | None) -> list[tuple[str, str]] | None:
    if not server_name:
        return None
    return [
        ("grpc.ssl_target_name_override", server_name),
        ("grpc.default_authority", server_name),
    ]


def rpc_details(exc: grpc.RpcError) -> str:
    try:
        code = exc.code()
    except Exception:  # pragma: no cover - defensive around grpc internals
        code = "unknown"
    try:
        details = exc.details()
    except Exception:  # pragma: no cover - defensive around grpc internals
        details = str(exc)
    return f"code={code} details={details}"


def compact_connection_info(info: dict[str, Any]) -> str:
    pieces = [f"status={info.get('status', 'ok')}"]
    if "info_permission" in info:
        pieces.append(f"info_permission={info.get('info_permission')}")
    if "invoice_permissions" in info:
        pieces.append(f"invoice_permissions={info.get('invoice_permissions')}")
    node_info = info.get("info")
    if isinstance(node_info, dict):
        for key in ("version", "chains"):
            if key in node_info:
                pieces.append(f"{key}={node_info[key]}")
    return " ".join(pieces)


async def tls_ready(
    *,
    target: str,
    tls_path: Path,
    server_name: str | None,
    timeout: float,
) -> tuple[bool, str]:
    cert = tls_path.read_bytes()
    channel = grpc.aio.secure_channel(
        target,
        grpc.ssl_channel_credentials(root_certificates=cert),
        options=channel_options(server_name),
    )
    try:
        await asyncio.wait_for(channel.channel_ready(), timeout=timeout)
        return True, "READY"
    except Exception as exc:
        return False, f"FAIL {type(exc).__name__}: {exc}"
    finally:
        await channel.close()


async def probe_rpc(
    *,
    label: str,
    path: Path,
    host: str,
    port: int,
    tls_path: Path,
    server_name: str | None,
) -> None:
    print(f"\n== RPC probe: {label} ==")
    print(f"path: {path} ({stat_path(path)})")
    if not path.exists():
        return

    store = MacaroonStore(Path("/tmp/lnswitchboard-diagnose-macaroon.hex"), path)
    client = LNClient(
        host=host,
        port=port,
        macaroon_store=store,
        tls_path=tls_path,
        tls_server_name=server_name,
    )
    try:
        info = await client.check_connection()
        print(f"check_connection: OK {compact_connection_info(info)}")
    except grpc.RpcError as exc:
        print(f"check_connection: RPC_ERROR {rpc_details(exc)}")
    except Exception as exc:
        print(f"check_connection: ERROR {type(exc).__name__}: {exc}")

    try:
        channels = await client.list_channels()
        print(f"list_channels: OK count={len(channels)}")
    except grpc.RpcError as exc:
        print(f"list_channels: RPC_ERROR {rpc_details(exc)}")
    except Exception as exc:
        print(f"list_channels: ERROR {type(exc).__name__}: {exc}")
    finally:
        await client.close()


def default_paths() -> tuple[Path, Path, Path]:
    invoice_raw = os.environ.get("LND_MACAROON_PATH", "")
    invoice_path = Path(invoice_raw) if invoice_raw else Path()
    explicit_readonly = os.environ.get("LND_READONLY_MACAROON_PATH")
    readonly_path = (
        Path(explicit_readonly)
        if explicit_readonly
        else invoice_path.with_name("readonly.macaroon")
        if invoice_path.name
        else Path()
    )
    invoices_path = (
        invoice_path.with_name("invoices.macaroon") if invoice_path.name else Path()
    )
    return invoice_path, readonly_path, invoices_path


def mounted_makaroons(chain_dir: Path) -> list[Path]:
    if not chain_dir.exists():
        return []
    return sorted(chain_dir.glob("*/*.macaroon"))


async def run_diagnostics(args: argparse.Namespace) -> int:
    host = os.environ.get("LND_HOST", "")
    port = int(os.environ.get("LND_GRPC_PORT", "10009"))
    target = f"{host}:{port}"
    tls_path = Path(os.environ.get("LND_TLS_PATH", "/lnd/tls.cert"))
    invoice_path, readonly_path, invoices_path = default_paths()

    print("lnSwitchboard LND diagnostics")
    print("=============================")
    print(f"container hostname: {os.uname().nodename}")
    print(f"LND_HOST={host}")
    print(f"LND_GRPC_PORT={port}")
    print(f"LND_TLS_PATH={tls_path} ({stat_path(tls_path)})")
    print(f"LND_MACAROON_PATH={invoice_path} ({stat_path(invoice_path)})")
    print(f"LND_READONLY_MACAROON_PATH={os.environ.get('LND_READONLY_MACAROON_PATH', '')}")
    print(f"derived readonly path={readonly_path} ({stat_path(readonly_path)})")
    print(f"plural invoices path={invoices_path} ({stat_path(invoices_path)})")

    print("\nMounted macaroon files:")
    chain_dir = Path("/lnd/data/chain/bitcoin")
    macaroons = mounted_makaroons(chain_dir)
    if macaroons:
        for macaroon in macaroons:
            print(f"- {macaroon} ({stat_path(macaroon)})")
    else:
        print(f"- no macaroon files found under {chain_dir}")

    decoded: dict[str, Any] = {}
    print("\nTLS certificate:")
    try:
        decoded = ssl._ssl._test_decode_cert(str(tls_path))
        print(f"subject={decoded.get('subject')}")
        print(f"subjectAltName={decoded.get('subjectAltName')}")
    except Exception as exc:
        print(f"decode failed: {type(exc).__name__}: {exc}")

    dns_names, ip_names = cert_names(decoded)
    candidates: list[str] = []
    add_unique(candidates, args.server_name)
    add_unique(candidates, os.environ.get("LND_TLS_SERVER_NAME"))
    for name in dns_names:
        add_unique(candidates, name)
    for name in ip_names:
        add_unique(candidates, name)
    for name in DEFAULT_TEST_NAMES:
        add_unique(candidates, name)

    print("\nTLS readiness:")
    ready_server_name: str | None = None
    default_ready = False
    if host and tls_path.exists():
        default_ready, default_message = await tls_ready(
            target=target,
            tls_path=tls_path,
            server_name=None,
            timeout=args.timeout,
        )
        print(f"- default target verification: {default_message}")
        if default_ready:
            ready_server_name = None
        for candidate in candidates:
            ready, message = await tls_ready(
                target=target,
                tls_path=tls_path,
                server_name=candidate,
                timeout=args.timeout,
            )
            print(f"- override={candidate}: {message}")
            if ready and ready_server_name is None and not default_ready:
                ready_server_name = candidate
    else:
        print("- skipped; LND_HOST or LND_TLS_PATH is missing")

    print("\nSelected TLS server name for RPC probes:")
    if default_ready:
        print("- default verification works; no override selected")
    elif ready_server_name:
        print(f"- using override={ready_server_name}")
    else:
        print("- no working TLS candidate found")

    if not args.skip_rpc and host and tls_path.exists():
        await probe_rpc(
            label="invoice.macaroon",
            path=invoice_path,
            host=host,
            port=port,
            tls_path=tls_path,
            server_name=ready_server_name,
        )
        await probe_rpc(
            label="readonly.macaroon",
            path=readonly_path,
            host=host,
            port=port,
            tls_path=tls_path,
            server_name=ready_server_name,
        )
        await probe_rpc(
            label="invoices.macaroon",
            path=invoices_path,
            host=host,
            port=port,
            tls_path=tls_path,
            server_name=ready_server_name,
        )

    print("\nLikely config outcome:")
    if ready_server_name:
        print(f"- Set LND_TLS_SERVER_NAME={ready_server_name}")
    elif default_ready:
        print("- Do not set LND_TLS_SERVER_NAME")
    else:
        print("- TLS still fails. Check that LND_TLS_PATH belongs to LND_HOST.")
    if readonly_path.exists():
        print(f"- Set LND_READONLY_MACAROON_PATH={readonly_path} for liquidity")
    else:
        print("- readonly.macaroon was not found at the derived path")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Diagnose lnSwitchboard's mounted LND TLS and macaroon setup.",
    )
    parser.add_argument(
        "--server-name",
        default=None,
        help="TLS server-name override to test first.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Seconds to wait for each TLS readiness probe.",
    )
    parser.add_argument(
        "--skip-rpc",
        action="store_true",
        help="Only inspect files/certificate and skip LND RPC probes.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    return asyncio.run(run_diagnostics(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
