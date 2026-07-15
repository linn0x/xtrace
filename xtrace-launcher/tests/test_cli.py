import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from xtrace_launcher.cli import (
    build_chromium_command,
    build_validate_command,
    default_validator_script,
    main,
    make_log_path,
    resolve_chromium_executable,
)


class LauncherTests(unittest.TestCase):
    def test_make_log_path_uses_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 6, 27, 12, 34, 56, tzinfo=timezone.utc)
            path = make_log_path(Path(tmp), now=now)
            self.assertEqual(path.name, "trace_20260627_123456.ndjson")
            self.assertEqual(path.parent, Path(tmp))

    def test_resolve_chromium_app_executable(self):
        app = Path("/tmp/Chromium.app")
        expected = app / "Contents" / "MacOS" / "Chromium"
        self.assertEqual(resolve_chromium_executable(app), expected)

    def test_build_command_sets_xtrace_flags_and_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path("/tmp/Chromium.app")
            log_dir = Path(tmp)
            now = datetime(2026, 6, 27, 12, 34, 56, tzinfo=timezone.utc)
            command, env, log_path, profile_path = build_chromium_command(
                chromium=chromium,
                url="http://127.0.0.1:8000/fingerprint-smoke.html",
                log_dir=log_dir,
                now=now,
            )

            resolved_chromium = str((Path("/tmp/Chromium.app")).resolve() / "Contents" / "MacOS" / "Chromium")
            self.assertEqual(command[0], resolved_chromium)
            self.assertIn("--xtrace-enable", command)
            self.assertIn(f"--xtrace-file={log_path}", command)
            self.assertTrue(Path(log_path).is_absolute())
            self.assertTrue(Path(profile_path).is_absolute())
            self.assertIn("--xtrace-categories=reverse,fingerprint", command)
            self.assertIn("--xtrace-capture-values=full", command)
            self.assertIn("--xtrace-capture-assets=full", command)
            self.assertFalse(any(arg.startswith("--xtrace-max-value-bytes=") for arg in command))
            self.assertFalse(any(arg.startswith("--xtrace-asset-max-bytes=") for arg in command))
            self.assertIn(f"--user-data-dir={profile_path}", command)
            self.assertEqual(command[-1], "http://127.0.0.1:8000/fingerprint-smoke.html")
            self.assertEqual(env["XTRACE_ENABLE"], "1")
            self.assertEqual(env["XTRACE_FILE"], os.fspath(log_path))
            self.assertEqual(env["XTRACE_CATEGORIES"], "reverse,fingerprint")
            self.assertEqual(env["XTRACE_CAPTURE_VALUES"], "full")
            self.assertEqual(env["XTRACE_CAPTURE_ASSETS"], "full")
            self.assertNotIn("XTRACE_MAX_VALUE_BYTES", env)
            self.assertNotIn("XTRACE_ASSET_MAX_BYTES", env)
            self.assertNotIn("XTRACE_MAX_BODY_BYTES", env)
            self.assertNotIn("XTRACE_MAX_HEADER_VALUE_BYTES", env)
            self.assertTrue(profile_path.name.startswith("profile_20260627_123456"))

    def test_build_command_resolves_relative_log_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp).resolve()
            prev = Path.cwd()
            try:
                os.chdir(cwd)
                command, env, log_path, profile_path = build_chromium_command(
                    chromium=Path("/tmp/Chromium.app"),
                    url="https://example.test",
                    log_dir=Path("rel-logs"),
                )
            finally:
                os.chdir(prev)
            self.assertTrue(log_path.is_absolute())
            self.assertTrue(str(log_path).startswith(str(cwd)))
            self.assertEqual(env["XTRACE_FILE"], os.fspath(log_path))
            self.assertTrue(profile_path.is_absolute())
            self.assertTrue(log_path.exists() or log_path.parent.exists())

    def test_build_command_allows_xtrace_config_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path("/tmp/Chromium.app")
            command, env, _, _ = build_chromium_command(
                chromium=chromium,
                url="https://example.test",
                log_dir=Path(tmp),
                categories="reverse",
                capture_values="args-only",
                capture_assets="off",
            )

            self.assertIn("--xtrace-categories=reverse", command)
            self.assertIn("--xtrace-capture-values=args-only", command)
            self.assertIn("--xtrace-capture-assets=off", command)
            self.assertFalse(any(arg.startswith("--xtrace-max-value-bytes=") for arg in command))
            self.assertFalse(any(arg.startswith("--xtrace-asset-max-bytes=") for arg in command))
            self.assertEqual(env["XTRACE_CATEGORIES"], "reverse")
            self.assertEqual(env["XTRACE_CAPTURE_VALUES"], "args-only")
            self.assertEqual(env["XTRACE_CAPTURE_ASSETS"], "off")
            self.assertNotIn("XTRACE_MAX_VALUE_BYTES", env)
            self.assertNotIn("XTRACE_ASSET_MAX_BYTES", env)
            self.assertNotIn("XTRACE_MAX_BODY_BYTES", env)
            self.assertNotIn("XTRACE_MAX_HEADER_VALUE_BYTES", env)

    def test_build_command_allows_explicit_body_and_header_caps(self):
        with tempfile.TemporaryDirectory() as tmp:
            command, env, _, _ = build_chromium_command(
                chromium=Path("/tmp/Chromium.app"),
                url="https://example.test",
                log_dir=Path(tmp),
                max_body_bytes=65536,
                max_header_value_bytes=2048,
            )

            self.assertIn("--xtrace-max-body-bytes=65536", command)
            self.assertIn("--xtrace-max-header-value-bytes=2048", command)
            self.assertEqual(env["XTRACE_MAX_BODY_BYTES"], "65536")
            self.assertEqual(env["XTRACE_MAX_HEADER_VALUE_BYTES"], "2048")

    def test_build_command_uses_unique_profile_for_same_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path("/tmp/Chromium.app")
            log_dir = Path(tmp)
            now = datetime(2026, 6, 27, 12, 34, 56, tzinfo=timezone.utc)

            _, _, first_log_path, first_profile_path = build_chromium_command(
                chromium=chromium,
                url="https://example.test/first",
                log_dir=log_dir,
                now=now,
            )
            _, _, second_log_path, second_profile_path = build_chromium_command(
                chromium=chromium,
                url="https://example.test/second",
                log_dir=log_dir,
                now=now,
            )

            self.assertEqual(first_log_path, second_log_path)
            self.assertNotEqual(first_profile_path, second_profile_path)
            self.assertTrue(first_profile_path.name.startswith("profile_20260627_123456_"))
            self.assertTrue(second_profile_path.name.startswith("profile_20260627_123456_"))

    def test_build_validate_command_defaults_to_business_api_strict_capture(self):
        trace = Path("/tmp/online-item-list.ndjson")
        command = build_validate_command(trace=trace)

        self.assertEqual(command[0], os.fspath(Path(sys.executable)))
        self.assertEqual(command[1], os.fspath(default_validator_script()))
        self.assertIn("--profile", command)
        self.assertIn("generic-vmp", command)
        self.assertIn("--strict-capture", command)
        self.assertEqual(command[-1], os.fspath(trace))

    def test_main_missing_executable_returns_2_without_creating_log_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path(tmp) / "missing-chromium"
            log_dir = Path(tmp) / "logs"
            stderr = io.StringIO()

            with patch("xtrace_launcher.cli.subprocess.Popen") as popen, contextlib.redirect_stderr(stderr):
                result = main(
                    [
                        "run",
                        "--chromium",
                        os.fspath(chromium),
                        "--url",
                        "https://example.test",
                        "--log-dir",
                        os.fspath(log_dir),
                    ]
                )

            self.assertEqual(result, 2)
            popen.assert_not_called()
            self.assertFalse(log_dir.exists())
            self.assertIn("Chromium executable not found", stderr.getvalue())

    def test_main_launches_executable_with_env_and_extra_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path(tmp) / "Chromium"
            chromium.write_text("#!/bin/sh\n", encoding="utf-8")
            chromium.chmod(0o755)
            log_dir = Path(tmp) / "logs"
            stdout = io.StringIO()

            with patch("xtrace_launcher.cli.subprocess.Popen") as popen, contextlib.redirect_stdout(stdout):
                popen.return_value.wait.return_value = 7
                result = main(
                    [
                        "run",
                        "--chromium",
                        os.fspath(chromium),
                        "--url",
                        "https://example.test",
                        "--log-dir",
                        os.fspath(log_dir),
                        "--extra-arg=--disable-gpu",
                        "--extra-arg=--remote-debugging-port=0",
                        "--xtrace-categories=reverse",
                        "--xtrace-capture-values=summary",
                        "--xtrace-capture-assets=full",
                    ]
                )

            self.assertEqual(result, 7)
            popen.assert_called_once()
            command = popen.call_args.args[0]
            env = popen.call_args.kwargs["env"]
            log_flag = next(arg for arg in command if arg.startswith("--xtrace-file="))
            profile_flag = next(arg for arg in command if arg.startswith("--user-data-dir="))
            log_path = Path(log_flag.split("=", 1)[1])
            profile_path = Path(profile_flag.split("=", 1)[1])

            self.assertEqual(command[0], os.fspath(chromium.resolve()))
            self.assertIn("--xtrace-enable", command)
            self.assertIn("--xtrace-categories=reverse", command)
            self.assertIn("--xtrace-capture-values=summary", command)
            self.assertIn("--xtrace-capture-assets=full", command)
            self.assertFalse(any(arg.startswith("--xtrace-max-value-bytes=") for arg in command))
            self.assertFalse(any(arg.startswith("--xtrace-asset-max-bytes=") for arg in command))
            self.assertEqual(command[-3:], ["--disable-gpu", "--remote-debugging-port=0", "https://example.test"])
            self.assertEqual(env["XTRACE_ENABLE"], "1")
            self.assertEqual(env["XTRACE_FILE"], os.fspath(log_path))
            self.assertEqual(env["XTRACE_CATEGORIES"], "reverse")
            self.assertEqual(env["XTRACE_CAPTURE_VALUES"], "summary")
            self.assertEqual(env["XTRACE_CAPTURE_ASSETS"], "full")
            self.assertNotIn("XTRACE_MAX_VALUE_BYTES", env)
            self.assertNotIn("XTRACE_ASSET_MAX_BYTES", env)
            self.assertNotIn("XTRACE_MAX_BODY_BYTES", env)
            self.assertNotIn("XTRACE_MAX_HEADER_VALUE_BYTES", env)
            self.assertEqual(log_path.parent, log_dir.resolve())
            self.assertEqual(profile_path.parent, (log_dir / "profiles").resolve())

    def test_main_run_rejects_success_without_trace_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path(tmp) / "Chromium"
            chromium.write_text("#!/bin/sh\n", encoding="utf-8")
            chromium.chmod(0o755)
            log_dir = Path(tmp) / "logs"
            stderr = io.StringIO()

            with (
                patch("xtrace_launcher.cli.subprocess.Popen") as popen,
                contextlib.redirect_stderr(stderr),
            ):
                popen.return_value.wait.return_value = 0
                result = main([
                    "run",
                    "--chromium",
                    os.fspath(chromium),
                    "--url",
                    "https://example.test",
                    "--log-dir",
                    os.fspath(log_dir),
                ])

            self.assertEqual(result, 1)
            popen.assert_called_once()
            self.assertIn("XTrace log was not created or is empty", stderr.getvalue())

    def test_main_run_can_validate_trace_after_chromium_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path(tmp) / "Chromium"
            chromium.write_text("#!/bin/sh\n", encoding="utf-8")
            chromium.chmod(0o755)
            log_dir = Path(tmp) / "logs"
            stdout = io.StringIO()

            with (
                patch("xtrace_launcher.cli.subprocess.Popen") as popen,
                patch("xtrace_launcher.cli.trace_file_has_records", return_value=True),
                patch("xtrace_launcher.cli.subprocess.run") as run,
                contextlib.redirect_stdout(stdout),
            ):
                popen.return_value.wait.return_value = 0
                run.return_value.returncode = 5
                result = main([
                    "run",
                    "--chromium",
                    os.fspath(chromium),
                    "--url",
                    "https://example.test",
                    "--log-dir",
                    os.fspath(log_dir),
                    "--validate-after-exit",
                ])

            self.assertEqual(result, 5)
            popen.assert_called_once()
            run.assert_called_once()
            launch_command = popen.call_args.args[0]
            validator_command = run.call_args.args[0]
            log_flag = next(arg for arg in launch_command if arg.startswith("--xtrace-file="))
            log_path = Path(log_flag.split("=", 1)[1])
            self.assertIn("--profile", validator_command)
            self.assertIn("generic-vmp", validator_command)
            self.assertIn("--strict-capture", validator_command)
            self.assertEqual(validator_command[-1], os.fspath(log_path))

    def test_main_run_can_capture_for_fixed_duration_then_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path(tmp) / "Chromium"
            chromium.write_text("#!/bin/sh\n", encoding="utf-8")
            chromium.chmod(0o755)
            log_dir = Path(tmp) / "logs"
            stdout = io.StringIO()

            with (
                patch("xtrace_launcher.cli.subprocess.Popen") as popen,
                patch("xtrace_launcher.cli.trace_file_has_records", return_value=True),
                patch("xtrace_launcher.cli.subprocess.run") as run,
                contextlib.redirect_stdout(stdout),
            ):
                process = popen.return_value
                process.wait.side_effect = [
                    subprocess.TimeoutExpired(cmd="Chromium", timeout=1.0),
                    0,
                ]
                run.return_value.returncode = 0
                result = main([
                    "run",
                    "--chromium",
                    os.fspath(chromium),
                    "--url",
                    "https://example.test",
                    "--log-dir",
                    os.fspath(log_dir),
                    "--capture-seconds",
                    "1",
                    "--validate-after-exit",
                ])

            self.assertEqual(result, 0)
            process.wait.assert_any_call(timeout=1.0)
            process.terminate.assert_called_once()
            run.assert_called_once()
            validator_command = run.call_args.args[0]
            self.assertIn("--strict-capture", validator_command)

    def test_main_validate_runs_strict_capture_validator(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            trace.write_text("", encoding="utf-8")

            with patch("xtrace_launcher.cli.subprocess.run") as run:
                run.return_value.returncode = 3
                result = main(["validate", os.fspath(trace)])

            self.assertEqual(result, 3)
            run.assert_called_once()
            command = run.call_args.args[0]
            self.assertEqual(command[0], os.fspath(Path(sys.executable)))
            self.assertIn("--profile", command)
            self.assertIn("generic-vmp", command)
            self.assertIn("--strict-capture", command)
            self.assertEqual(command[-1], os.fspath(trace))


if __name__ == "__main__":
    unittest.main()
