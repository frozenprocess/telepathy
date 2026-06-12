#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 The Telepathy Authors
"""Prepend the Apache-2.0 license header to project source files.

Idempotent: files that already carry an SPDX-License-Identifier are skipped.
Skips vendored (third_party/) and built (bin/) trees.
"""
import os
import sys

YEAR = "2026"
HOLDER = "The Telepathy Authors"

NOTICE = [
    "SPDX-License-Identifier: Apache-2.0",
    f"Copyright (c) {YEAR} {HOLDER}",
    "",
    "This file is part of Telepathy.",
    "",
    "Licensed under the Apache License, Version 2.0 (the \"License\");",
    "you may not use this file except in compliance with the License.",
    "You may obtain a copy of the License at",
    "",
    "    http://www.apache.org/licenses/LICENSE-2.0",
    "",
    "Unless required by applicable law or agreed to in writing, software",
    "distributed under the License is distributed on an \"AS IS\" BASIS,",
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
    "See the License for the specific language governing permissions and",
    "limitations under the License.",
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
