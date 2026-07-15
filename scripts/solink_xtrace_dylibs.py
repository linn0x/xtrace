#!/usr/bin/env python3
"""Manually recompile + solink XTrace-touched Chromium dylibs.

Use when ninja's dependency graph is too slow/stale (e.g. after wiping
.ninja_log or siso conflicts) but objects under out/XTrace are mostly intact.

Targets:
  - libv8.dylib          (runtime-typedarray.cc / AppendFieldPrefix)
  - libchrome_dll.dylib  (chrome_content_browser_client.cc / BrowserNetwork body)

Component-build load path:
  Chromium.app -> Chromium Framework -> @rpath/libchrome_dll.dylib -> libv8.dylib
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path


def ninja_tokenize(s: str) -> list[str]:
    """Split a ninja variable value into argv tokens (preserve \\\" as \")."""
    s = s.replace("$$", "\0")
    tokens: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        while i < n and s[i].isspace():
            i += 1
        if i >= n:
            break
        tok: list[str] = []
        while i < n and not s[i].isspace():
            if s[i] == "\\" and i + 1 < n and s[i + 1] in '"$\\':
                tok.append(s[i + 1])
                i += 2
                continue
            tok.append(s[i])
            i += 1
        tokens.append("".join(tok).replace("\0", "$"))
    return tokens


def load_target_globals(ninja_path: Path) -> dict[str, str]:
    g: dict[str, str] = {}
    for line in ninja_path.read_text(errors="ignore").splitlines():
        if line.startswith("build "):
            break
        if " = " in line and not line.startswith(" ") and not line.startswith("rule "):
            k, v = line.split(" = ", 1)
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
                g[k] = v
    return g


def parse_solink(ninja_path: Path, target_token: str) -> tuple[list[str], dict[str, str]]:
    lines = ninja_path.read_text(errors="ignore").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("build ") and ": solink " in line and target_token in line:
            m = re.match(r"build\s+(.+?):\s+solink\s+(.+)$", line)
            if not m:
                continue
            rest = m.group(2)
            if " || " in rest:
                rest = rest.split(" || ", 1)[0]
            if " | " in rest:
                rest = rest.split(" | ", 1)[0]
            objects = rest.split()
            vars_: dict[str, str] = {}
            for j in range(i + 1, len(lines)):
                if not lines[j].startswith("  "):
                    break
                if " = " in lines[j]:
                    k, v = lines[j][2:].split(" = ", 1)
                    vars_[k] = v
            return objects, vars_
    raise RuntimeError(f"no solink edge for {target_token} in {ninja_path}")


def compile_one(out: Path, obj_ninja: Path, src_rel: str, out_o: str) -> None:
    g = load_target_globals(obj_ninja)
    cmd = (
        [
            "../../third_party/llvm-build/Release+Asserts/bin/clang++",
            "-MMD",
            "-MF",
            out_o + ".d",
        ]
        + ninja_tokenize(g["defines"])
        + ninja_tokenize(g["include_dirs"])
        + ninja_tokenize(g["cflags"])
        + ninja_tokenize(g["cflags_cc"])
        + ninja_tokenize(g.get("module_deps", ""))
        + [
            f'-fmodule-name={g["cc_module_name"]}_Private',
            "-c",
            src_rel,
            "-o",
            out_o,
        ]
    )
    print(f"CXX {out_o}", flush=True)
    t0 = time.time()
    r = subprocess.run(cmd, cwd=str(out))
    if r.returncode != 0:
        raise SystemExit(f"compile failed for {out_o} (exit {r.returncode})")
    size = (out / out_o).stat().st_size
    print(f"  ok in {time.time() - t0:.1f}s size={size}", flush=True)


def solink_one(out: Path, edge_ninja: Path, target_token: str, name: str) -> None:
    objects, vars_ = parse_solink(edge_ninja, target_token)
    missing = [o for o in objects if not (out / o).exists()]
    if missing:
        raise SystemExit(f"{name}: missing {len(missing)} objects, e.g. {missing[:5]}")
    rsp_parts = objects[:]
    for extra in (
        vars_.get("frameworks", ""),
        vars_.get("swiftmodules", ""),
        vars_.get("solibs", ""),
        vars_.get("libs", ""),
    ):
        if extra.strip():
            rsp_parts.extend(extra.split())
    (out / f"{name}.dylib.rsp").write_text(" ".join(rsp_parts) + "\n")
    cmd = [
        "python3",
        "../../build/toolchain/apple/linker_driver.py",
        "-Wcrl,otoolpath,../../third_party/llvm-build/Release+Asserts/bin/llvm-otool",
        "-Wcrl,nmpath,../../third_party/llvm-build/Release+Asserts/bin/llvm-nm",
        f"-Wcrl,tocname,./{name}.dylib.TOC",
        "-Wcrl,driver,../../third_party/llvm-build/Release+Asserts/bin/clang++",
        "-Wcrl,strippath,../../third_party/llvm-build/Release+Asserts/bin/llvm-strip",
        "-Wcrl,installnametoolpath,../../third_party/llvm-build/Release+Asserts/bin/llvm-install-name-tool",
        "-shared",
        f"-Wl,-install_name,@rpath/{name}.dylib",
    ]
    cmd.extend(ninja_tokenize(vars_["ldflags"]))
    cmd.extend(["-o", f"./{name}.dylib", f"@./{name}.dylib.rsp"])
    if vars_.get("rlibs", "").strip():
        cmd.extend(vars_["rlibs"].split())
    print(f"SOLINK {name}.dylib ({len(objects)} objs)", flush=True)
    t0 = time.time()
    r = subprocess.run(cmd, cwd=str(out), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        sys.stderr.write((r.stdout or "")[-4000:] + "\n")
        raise SystemExit(f"solink failed for {name} (exit {r.returncode})")
    size = (out / f"{name}.dylib").stat().st_size
    print(f"  ok in {time.time() - t0:.1f}s size={size}", flush=True)


def codesign_outputs(out: Path, dylib_names: list[str]) -> None:
    for name in dylib_names:
        subprocess.run(
            ["codesign", "--force", "--sign", "-", str(out / f"{name}.dylib")],
            check=True,
        )
    app = out / "Chromium.app"
    if app.exists():
        subprocess.run(["codesign", "--force", "--deep", "--sign", "-", str(app)], check=True)
        print("codesign Chromium.app ok", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="out/XTrace path (default: <repo>/chromium/src/out/XTrace)",
    )
    parser.add_argument("--skip-compile", action="store_true")
    parser.add_argument("--only", choices=["v8", "chrome", "both"], default="both")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[1]
    out = (args.out or root / "chromium/src/out/XTrace").resolve()
    if not out.is_dir():
        print(f"out dir missing: {out}", file=sys.stderr)
        return 2

    do_v8 = args.only in ("v8", "both")
    do_chrome = args.only in ("chrome", "both")
    signed: list[str] = []

    if not args.skip_compile:
        if do_v8:
            compile_one(
                out,
                out / "obj/v8/v8_base_without_compiler.ninja",
                "../../v8/src/runtime/runtime-typedarray.cc",
                "obj/v8/v8_base_without_compiler/runtime-typedarray.o",
            )
        if do_chrome:
            compile_one(
                out,
                out / "obj/chrome/browser/core.ninja",
                "../../chrome/browser/chrome_content_browser_client.cc",
                "obj/chrome/browser/core/chrome_content_browser_client.o",
            )

    if do_v8:
        solink_one(out, out / "obj/v8/v8.ninja", "libv8.dylib", "libv8")
        signed.append("libv8")
    if do_chrome:
        solink_one(out, out / "obj/chrome/chrome_dll.ninja", "libchrome_dll.dylib", "libchrome_dll")
        signed.append("libchrome_dll")

    codesign_outputs(out, signed)
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
