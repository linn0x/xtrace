from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_log_path(log_dir: Path, now: datetime | None = None) -> Path:
    timestamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d_%H%M%S")
    return log_dir / f"trace_{timestamp}.ndjson"


def resolve_chromium_executable(chromium: Path) -> Path:
    if chromium.suffix == ".app":
        return chromium / "Contents" / "MacOS" / "Chromium"
    return chromium


def default_validator_script() -> Path:
    return Path(__file__).resolve().parents[2] / "scripts" / "validate_trace.py"


def build_chromium_command(
    *,
    chromium: Path,
    url: str,
    log_dir: Path,
    now: datetime | None = None,
    extra_args: Iterable[str] = (),
    categories: str = "reverse,fingerprint",
    capture_values: str = "full",
    capture_assets: str = "full",
    causality: str = "off",
    max_body_bytes: int = 0,
    max_header_value_bytes: int = 0,
    capture_response_body: bool = False,
    remote_debugging_port: int = 0,
    user_data_dir: Path | None = None,
) -> tuple[list[str], dict[str, str], Path, Path]:
    # Chromium's browser process resolves --xtrace-file against its own cwd /
    # sandbox view. Relative log dirs often produce FILE_ERROR_ACCESS_DENIED.
    log_dir = Path(log_dir).expanduser().resolve()
    chromium = Path(chromium).expanduser().resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    effective_now = now or datetime.now(timezone.utc)
    timestamp = effective_now.strftime("%Y%m%d_%H%M%S")
    log_path = make_log_path(log_dir, now=effective_now).resolve()
    if user_data_dir is not None:
        # fixed profile: reuse a warm session (stable device/token cookies) across
        # runs -- needed for controlled-diff recipes.
        profile_path = Path(user_data_dir).expanduser().resolve()
    else:
        profile_path = (log_dir / "profiles" / f"profile_{timestamp}_{uuid.uuid4().hex}").resolve()
    profile_path.mkdir(parents=True, exist_ok=True)

    executable = resolve_chromium_executable(chromium)
    command = [
        os.fspath(executable),
        "--xtrace-enable",
        f"--xtrace-file={log_path}",
        f"--xtrace-categories={categories}",
        f"--xtrace-capture-values={capture_values}",
        f"--xtrace-capture-assets={capture_assets}",
        f"--xtrace-causality={causality}",
        f"--user-data-dir={profile_path}",
        "--no-first-run",
        "--no-default-browser-check",
        *list(extra_args),
        url,
    ]
    insert_at = 6
    if capture_response_body:
        command.insert(insert_at, "--xtrace-capture-response-body=1")
        insert_at += 1
    if max_body_bytes > 0:
        command.insert(insert_at, f"--xtrace-max-body-bytes={max_body_bytes}")
        insert_at += 1
    if max_header_value_bytes > 0:
        command.insert(
            insert_at,
            f"--xtrace-max-header-value-bytes={max_header_value_bytes}",
        )
    if remote_debugging_port > 0:
        # CDP endpoint for --inject-api-hooks. --remote-allow-origins is required
        # for a non-browser CDP client to attach on recent Chromium.
        command.insert(len(command) - 1, f"--remote-debugging-port={remote_debugging_port}")
        command.insert(len(command) - 1, "--remote-allow-origins=*")

    env = os.environ.copy()
    env["XTRACE_ENABLE"] = "1"
    env["XTRACE_FILE"] = os.fspath(log_path)
    env["XTRACE_CATEGORIES"] = categories
    env["XTRACE_CAPTURE_VALUES"] = capture_values
    env["XTRACE_CAPTURE_ASSETS"] = capture_assets
    env["XTRACE_CAUSALITY"] = causality
    env["XTRACE_CAPTURE_RESPONSE_BODY"] = "1" if capture_response_body else "0"
    if max_body_bytes > 0:
        env["XTRACE_MAX_BODY_BYTES"] = str(max_body_bytes)
    if max_header_value_bytes > 0:
        env["XTRACE_MAX_HEADER_VALUE_BYTES"] = str(max_header_value_bytes)
    return command, env, log_path, profile_path


def build_validate_command(
    *,
    trace: Path,
    validator: Path | None = None,
    profile: str = "generic-vmp",
    strict_capture: bool = True,
    schema_version: int | None = None,
    extra_args: Iterable[str] = (),
) -> list[str]:
    command = [
        os.fspath(Path(sys.executable)),
        os.fspath(validator or default_validator_script()),
        "--profile",
        profile,
    ]
    if strict_capture:
        command.append("--strict-capture")
    command.extend(extra_args)
    # Keep an explicitly selected schema authoritative over free-form validator
    # arguments. In particular, a sync causality capture must not accidentally
    # be validated as schema v1 by a repeated --schema-version option.
    if schema_version is not None:
        command.extend(["--schema-version", str(schema_version)])
    command.append(os.fspath(trace))
    return command


def trace_file_has_records(trace: Path) -> bool:
    return trace.exists() and trace.is_file() and trace.stat().st_size > 0


def wait_for_chromium(
    process: subprocess.Popen,
    *,
    capture_seconds: float | None = None,
    shutdown_timeout: float = 10.0,
) -> int:
    if capture_seconds is None:
        return process.wait()
    try:
        return process.wait(timeout=capture_seconds)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=shutdown_timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="xtrace-launcher")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="start a patched Chromium with XTrace enabled")
    run.add_argument("--chromium", required=True, type=Path, help="path to Chromium.app or Chromium executable")
    run.add_argument("--url", required=True, help="URL to open")
    run.add_argument("--log-dir", required=True, type=Path, help="directory for NDJSON logs")
    run.add_argument("--xtrace-categories", default="reverse,fingerprint")
    run.add_argument("--xtrace-capture-values", choices=["full", "summary", "args-only"], default="full")
    run.add_argument("--xtrace-capture-assets", choices=["off", "summary", "full"], default="full")
    run.add_argument(
        "--xtrace-causality",
        choices=["off", "sync"],
        default="off",
        help="opt-in schema v2 synchronous renderer causality; default preserves schema v1",
    )
    run.add_argument(
        "--xtrace-max-body-bytes",
        type=int,
        default=0,
        help="optional upload body cap when response-body capture is enabled; 0 uses default cap",
    )
    run.add_argument(
        "--xtrace-max-header-value-bytes",
        type=int,
        default=0,
        help="optional header value cap; 0 keeps full header capture",
    )
    run.add_argument(
        "--xtrace-capture-response-body",
        action="store_true",
        default=False,
        help=(
            "opt-in: tee BrowserNetwork response bodies into complete events "
            "(OFF by default; can blank heavy SPAs / stress network service)"
        ),
    )
    run.add_argument(
        "--inject-api-hooks",
        action="store_true",
        default=False,
        help=(
            "patch-free: inject a generic CDP preamble that wraps standard "
            "plaintext-boundary APIs (TextEncoder/crypto.subtle/JSON/btoa) and "
            "merges their I/O into the trace (complements native hooks)"
        ),
    )
    run.add_argument("--inject-port", type=int, default=0,
                     help="CDP port for --inject-api-hooks (0 = auto-pick a free port)")
    run.add_argument("--inject-scan-delay", type=int, default=4000,
                     help="ms to wait before installing the String.scan hook (lets the page hydrate)")
    run.add_argument("--inject-scan-cap", type=int, default=4096,
                     help="max chars/bytes kept per injected value -- String.scan AND the "
                          "crypto.subtle/TextEncoder/JSON boundary I/O (raise if pairing.json shows truncation)")
    run.add_argument("--user-data-dir", type=Path, default=None,
                     help="reuse a fixed Chromium profile dir (warm session) instead of a fresh one")
    run.add_argument("--extra-arg", action="append", default=[], help="extra Chromium argument; may be repeated")
    run.add_argument(
        "--capture-seconds",
        type=float,
        default=None,
        help="stop Chromium after N seconds and treat that stop as a completed capture",
    )
    run.add_argument(
        "--validate-after-exit",
        action="store_true",
        help="run the strict validator against this run's trace after Chromium exits successfully",
    )
    run.add_argument(
        "--validator",
        type=Path,
        default=None,
        help="path to scripts/validate_trace.py for --validate-after-exit",
    )
    run.add_argument("--validate-profile", choices=["business-api", "fingerprint", "generic-vmp", "reverse", "all"], default="generic-vmp")
    run.add_argument(
        "--no-strict-capture",
        action="store_false",
        dest="strict_capture",
        default=True,
        help="disable strict capture validation for --validate-after-exit",
    )
    run.add_argument(
        "--extra-validate-arg",
        action="append",
        default=[],
        help="extra validator argument for --validate-after-exit; may be repeated",
    )

    validate = subparsers.add_parser("validate", help="validate a captured XTrace NDJSON trace")
    validate.add_argument("trace", type=Path, help="NDJSON trace to validate")
    validate.add_argument(
        "--validator",
        type=Path,
        default=None,
        help="path to scripts/validate_trace.py; defaults to the repository copy",
    )
    validate.add_argument("--profile", choices=["business-api", "fingerprint", "generic-vmp", "reverse", "all"], default="generic-vmp")
    validate.add_argument(
        "--no-strict-capture",
        action="store_false",
        dest="strict_capture",
        default=True,
        help="disable the default strict capture preset",
    )
    validate.add_argument(
        "--extra-validate-arg",
        action="append",
        default=[],
        help="extra validator argument; may be repeated",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "run":
        if args.capture_seconds is not None and args.capture_seconds <= 0:
            print("--capture-seconds must be greater than 0", file=sys.stderr)
            return 2
        if args.xtrace_max_body_bytes < 0:
            print("--xtrace-max-body-bytes must be greater than or equal to 0", file=sys.stderr)
            return 2
        if args.xtrace_max_header_value_bytes < 0:
            print("--xtrace-max-header-value-bytes must be greater than or equal to 0", file=sys.stderr)
            return 2
        executable = resolve_chromium_executable(args.chromium)
        if not (executable.exists() and executable.is_file() and os.access(executable, os.X_OK)):
            print(f"Chromium executable not found or not executable: {executable}", file=sys.stderr)
            return 2
        inject_port = (args.inject_port or _free_port()) if args.inject_api_hooks else 0
        command, env, log_path, profile_path = build_chromium_command(
            chromium=args.chromium,
            # inject installs the hook pre-document, then navigates to the real URL
            url="about:blank" if args.inject_api_hooks else args.url,
            log_dir=args.log_dir,
            extra_args=args.extra_arg,
            categories=args.xtrace_categories,
            capture_values=args.xtrace_capture_values,
            capture_assets=args.xtrace_capture_assets,
            causality=args.xtrace_causality,
            max_body_bytes=args.xtrace_max_body_bytes,
            max_header_value_bytes=args.xtrace_max_header_value_bytes,
            capture_response_body=args.xtrace_capture_response_body,
            remote_debugging_port=inject_port,
            user_data_dir=args.user_data_dir,
        )
        print(f"XTrace log: {log_path}")
        print(f"XTrace profile: {profile_path}")
        process = subprocess.Popen(command, env=env)

        injector = None
        injected_path = log_path.with_name(log_path.stem + ".inject.ndjson")
        if args.inject_api_hooks:
            from . import inject

            stop_event = threading.Event()
            counter = {"n": 0}

            def _run():
                try:
                    counter["n"] = inject.run_injector(
                        inject_port, args.url, injected_path, stop_event,
                        scan_delay_ms=args.inject_scan_delay,
                        scan_cap=args.inject_scan_cap)
                except Exception as exc:  # never crash the run over injection
                    print(f"[inject] error: {exc}", file=sys.stderr)

            injector = threading.Thread(target=_run, daemon=True)
            injector.start()
            print(f"XTrace inject: CDP :{inject_port} -> {injected_path}")

        exit_code = wait_for_chromium(process, capture_seconds=args.capture_seconds)

        if injector is not None:
            stop_event.set()          # Chromium exit drops the CDP socket; recv unblocks
            injector.join(timeout=10)
            appended = inject.align_and_append(
                log_path, injected_path,
                schema_version=2 if args.xtrace_causality == "sync" else 1,
            )
            print(f"XTrace inject: {counter['n']} events captured, {appended} merged into trace")

        if exit_code != 0:
            return exit_code
        if not trace_file_has_records(log_path):
            print(f"XTrace log was not created or is empty: {log_path}", file=sys.stderr)
            return 1
        if not args.validate_after_exit:
            return 0
        validator = args.validator or default_validator_script()
        if not (validator.exists() and validator.is_file()):
            print(f"XTrace validator not found: {validator}", file=sys.stderr)
            return 2
        validate_command = build_validate_command(
            trace=log_path,
            validator=validator,
            profile=args.validate_profile,
            strict_capture=args.strict_capture,
            schema_version=2 if args.xtrace_causality == "sync" else None,
            extra_args=args.extra_validate_arg,
        )
        return subprocess.run(validate_command).returncode
    if args.command == "validate":
        validator = args.validator or default_validator_script()
        if not (validator.exists() and validator.is_file()):
            print(f"XTrace validator not found: {validator}", file=sys.stderr)
            return 2
        command = build_validate_command(
            trace=args.trace,
            validator=validator,
            profile=args.profile,
            strict_capture=args.strict_capture,
            extra_args=args.extra_validate_arg,
        )
        return subprocess.run(command).returncode
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
