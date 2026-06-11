#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 The Telepathy Authors
"""Prepend the GPL-3.0 license header to project source files.

Idempotent: files that already carry an SPDX-License-Identifier are skipped.
Skips vendored (third_party/) and built (bin/) trees.
"""
import os
import sys

YEAR = "2026"
HOLDER = "The Telepathy Authors"

NOTICE = [
    "SPDX-License-Identifier: GPL-3.0-only",
    f"Copyright (c) {YEAR} {HOLDER}",
    "",
    "This file is part of Telepathy.",
    "",
    "Telepathy is free software: you can redistribute it and/or modify it",
    "under the terms of the GNU General Public License version 3 as published",
    "by the Free Software Foundation.",
    "",
    "Telepathy is distributed in the hope that it will be useful, but WITHOUT",
    "ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or",
    "FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for",
    "more details.",
]


def block(prefix):
    return "\n".join((prefix + line).rstrip() for line in NOTICE)


def go_header():
    return block("// ") + "\n\n"


def sh_header():
    return block("# ") + "\n"


def process(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if "SPDX-License-Identifier" in content:
        return False
    if path.endswith(".go"):
        new = go_header() + content
    elif path.endswith(".sh"):
        if content.startswith("#!"):
            nl = content.index("\n") + 1
            shebang, rest = content[:nl], content[nl:]
            # drop a leading blank-comment line if present, header replaces it
            new = shebang + sh_header() + rest
        else:
            new = sh_header() + content
    else:
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    return True


def main(files):
    changed = 0
    for path in files:
        if process(path):
            print(f"headered: {path}")
            changed += 1
        else:
            print(f"skipped:  {path}")
    print(f"\n{changed} file(s) updated")


if __name__ == "__main__":
    main(sys.argv[1:])
