#!/usr/bin/env python3
"""Structural validation for the workflow files, using only the standard library.

Deliberately not PyYAML. The first version of this script imported yaml, which
is not installed on the runner's container — so the check meant to catch a
broken workflow failed on the very first thing it did.

More to the point, a YAML parser is the wrong tool for this job. The damage
this catches happens *inside* a `run: |` literal block: nothing is invalid
YAML, the shell script simply contains half a neighbouring step. Three separate
edits to the Gitea workflow did exactly that, all passed every yaml.safe_load —
including the one in CI — and one of them shipped:

    ./scripts/check-docker-base.sh Dockerfile.go-build with:
    ...
    fetch-depth: 0        -> fetch-depth:: command not found

So rather than parse the document into a tree and inspect it, this reads the
text and asks the question that matters: does any block scalar contain a line
that is plainly a YAML key?

Run: scripts/check-workflows.py
"""
import re
import sys
from pathlib import Path

# Keys that begin a step, a job, or a common `with:` block. None of these is
# ever the first word of a shell line, so finding one inside a `run:` block
# means a neighbouring step's body was spliced in.
STEP_KEYS = frozenset("""
    uses run name with env if needs id steps jobs on permissions
    runs-on outputs defaults concurrency timeout-minutes continue-on-error
    container services working-directory shell
    fetch-depth registry username password platform platforms push
    provenance sbom tags build-args cache-from cache-to context file
    labels go-version packages ref submodules path persist-credentials
    architectures fail-on-unmatched paths
""".split())

# Keys valid on any step. Read off the step's own lines, not from a parse tree:
# this script has no YAML dependency by design.
STEP_FIELDS = frozenset("""
    uses run name with env if id needs continue-on-error
    working-directory shell timeout-minutes
""".split())

STEP_ITEM = re.compile(r"^(\s*)-\s")

BLOCK_KEY = re.compile(r"^(\s*)([A-Za-z0-9_.-]+):\s*[|>][-+0-9]*\s*$")
KEY_LINE = re.compile(r"^(\s*)([A-Za-z][A-Za-z0-9_-]*):(\s|$)")

# A heredoc or multi-line string inside a script could legitimately contain a
# line like this. Nothing in these workflows does, and tracking heredocs would
# mean tracking quoting rules in a checker that exists to stay simple.
MAX_CONSECUTIVE_BLANKS = 2


def check_step_fields(lines, rel):
    """Flag step field combinations that cannot be what was intended.

    `with:` supplies inputs to a `uses:` step. A `run:` step with a `with:`
    block is not an error the runner reports — it is silently ignored — and it
    is the exact shape left behind when an edit inserts a step between a
    `uses:` line and that step's own `with:` block.

    That happened here: actions/setup-go was left with no go-version while the
    inserted step carried inputs it ignored. It parsed, it looked right, and
    nothing caught it — including the check in this file, which only looked
    inside run blocks.
    """
    problems = []
    i = 0
    while i < len(lines):
        m = STEP_ITEM.match(lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        start = i

        # A step's first key sits on the `- ` line itself: `- uses: x`,
        # `- run: y`, `- name: z`. Anything else beginning with a dash is a
        # list item somewhere else and is not a step.
        first = re.match(r"([A-Za-z][A-Za-z0-9_-]*):(\s|$)", lines[i][m.end():])
        if not first or first.group(1) not in STEP_FIELDS:
            i += 1
            continue

        fields = {first.group(1): i + 1}
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if not line.strip():
                j += 1
                continue
            cur = len(line) - len(line.lstrip())
            if cur <= indent:
                break
            if STEP_ITEM.match(line) and cur == indent:
                break
            km = re.match(r"^(\s*)([A-Za-z][A-Za-z0-9_-]*):(\s|$)", line)
            if km and (len(km.group(1)) - indent) <= 2 and km.group(2) in STEP_FIELDS:
                fields.setdefault(km.group(2), j + 1)
            j += 1
        i = j

        label = fields.get("name") or fields.get("uses") or f"step at line {start + 1}"
        where = rel + ":" + str(fields.get("name") or fields.get("uses") or start + 1)

        if "run" in fields and "with" in fields:
            problems.append(
                f"{where}: step {label!r} has both 'run' and 'with'.\n"
                f"      A `with:` block supplies inputs to a `uses:` step, so a "
                f"run step's is ignored.\n"
                f"      Almost always a `with:` block that drifted onto the wrong "
                f"step when one was inserted above it."
            )
        if "uses" in fields and "run" in fields:
            problems.append(f"{where}: step {label!r} has both 'uses' and 'run'.")
        if "uses" not in fields and "run" not in fields:
            problems.append(f"{where}: step {label!r} has neither 'uses' nor 'run'.")

    return problems


def check_file(path: Path, rel: str) -> list:
    problems = []
    lines = path.read_text().splitlines()
    problems.extend(check_step_fields(lines, rel))

    if not any(l.rstrip() == "jobs:" for l in lines):
        problems.append(f"{rel}: no top-level 'jobs:' key")

    in_block = False
    block_indent = 0
    block_key = ""
    block_start = 0
    blanks = 0

    for n, line in enumerate(lines, 1):
        if not in_block:
            m = BLOCK_KEY.match(line)
            if not m:
                continue
            in_block = True
            block_indent = len(m.group(1))
            block_key = m.group(2)
            block_start = n
            blanks = 0
            continue

        # Inside a block scalar until a non-blank line dedents to <= the key.
        if not line.strip():
            blanks += 1
            if blanks > MAX_CONSECUTIVE_BLANKS and in_block:
                # A run block with a big gap of blanks is still a run block,
                # but an unusually long one is worth knowing about.
                pass
            continue
        blanks = 0

        indent = len(line) - len(line.lstrip())
        if indent <= block_indent:
            in_block = False
            continue

        # Only a shell block can be spliced into. `name:` and `if:` blocks are
        # prose; a colon in them is ordinary.
        if block_key != "run":
            continue

        m = KEY_LINE.match(line)
        if not m:
            continue
        key = m.group(2)
        if key not in STEP_KEYS:
            continue
        problems.append(
            f"{rel}:{n}: the run block starting at line {block_start} contains "
            f"what looks like a YAML key\n"
            f"      {line.strip()!r}\n"
            f"    Usually a step body spliced into this shell script, which the "
            f"runner will try to execute.\n"
            f"    The one case this cannot tell apart is a heredoc carrying YAML "
            f"as data. None of these workflows does that."
        )

    return problems


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    files = sorted(
        list(root.glob(".gitea/workflows/*.yml")) + list(root.glob(".github/workflows/*.yml"))
    )
    if not files:
        print("error: no workflow files found", file=sys.stderr)
        return 1

    problems = []
    for f in files:
        rel = str(f.relative_to(root))
        try:
            found = check_file(f, rel)
        except Exception as exc:
            problems.append(f"{rel}: could not be read: {exc}")
            found = []
        problems.extend(found)
        print(f"  {'✗' if found else '✓'} {rel}")

    if problems:
        print(file=sys.stderr)
        for p in problems:
            print(f"  ✗ {p}", file=sys.stderr)
        print(f"\n{len(problems)} structural problem(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())