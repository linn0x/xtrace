#!/usr/bin/env python3
"""Deprecated shim: superseded by `sign_pipeline.py explain`.

Kept so existing commands keep working. Flags are translated:
  --script-filter S -> --script S     (S='' now means auto-detect, not "all scripts")
  --anchor-param P  -> --carrier P
  --token-param T   -> --token T
Everything else (--trace/--out/--window-ms/--anchor-index) passes through.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sign_pipeline  # noqa: E402


def _translate(argv):
    out = ["explain"]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--script-filter":
            out += ["--script", (argv[i + 1] or "auto")]; i += 2
        elif a == "--anchor-param":
            out += ["--carrier", argv[i + 1]]; i += 2
        elif a == "--token-param":
            out += ["--token", argv[i + 1]]; i += 2
        else:
            out.append(a); i += 1
    return out


if __name__ == "__main__":
    print("note: extract_sign_window.py is deprecated; use `sign_pipeline.py explain`.",
          file=sys.stderr)
    raise SystemExit(sign_pipeline.main(_translate(sys.argv[1:])))
