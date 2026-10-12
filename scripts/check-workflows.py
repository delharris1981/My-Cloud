#!/usr/bin/env python3
"""Structural validation for the workflow files.

yaml.safe_load is not enough. A workflow can parse cleanly and still be broken,
because the damage happens *inside* a `run: |` literal block: nothing is
invalid YAML, the shell script simply contains half a step. Three separate
edits to the Gitea workflow did exactly this, and all three passed every
YAML parse — including the one in CI, which is why they reached a runner.

The third of those spliced `with:` and `fetch-depth: 0` into a run block, and
the runner executed:

    ./scripts/check-docker-base.sh Dockerfile.go-build with:
    ...
    fetch-depth: 0        -> fetch-depth:: command not found

So the check that matters is not "is this YAML valid" but "does every step
look like a step, and does every run block look like a shell script".

Run: scripts/check-workflows.py
"""
import re
import sys
from pathlib import Path

import yaml

# Keys that may legitimately start a line inside a `run:` block. Nothing here
# is ever a YAML key at the start of a shell line, so seeing one means a
# neighbouring step's body was spliced in.
STEP_KEYS = {
    "uses", "run", "name", "with", "env", "if", "needs", "id", "steps",
    "jobs", "on", "permissions", "container", "services", "runs-on",
    "outputs", "defaults", "concurrency", "timeout-minutes",
    # keys that appear in `with:` blocks and are the usual splice payload
    "fetch-depth", "registry", "username", "password", "platforms", "push",
    "provenance", "sbom", "tags", "build-args", "cache-from", "cache-to",
    "context", "file", "labels", "go-version", "packages",
}

STEP_LINE = re.compile(r"^(\s*)([A-Za-z][A-Za-z0-9_-]*):(\s|$)")

problems = []


def check_run_block(job: str, index: int, name: str, script: str) -> None:
    for lineno, line in enumerate(script.splitlines(), 1):
        m = STEP_LINE.match(line)
        if not m:
            continue
        key = m.group(2)
        if key in STEP_KEYS:
            problems.append(
                f"{job}: step {index} ({name!r}) line {lineno} of its run block "
                f"starts with {key!r}: {line.strip()!r}\n"
                f"    A YAML key inside a shell script means another step's body "
                f"was spliced in. The runner will try to execute it as a command."
            )


def check_workflow(path: Path) -> None:
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict):
        problems.append(f"{path}: top level is {type(doc).__name__}, expected a mapping")
        return
    if "jobs" not in doc:
        problems.append(f"{path}: no 'jobs' key")
        return
    # 'on' parses as the boolean True in YAML 1.1, so accept either spelling.
    if True not in doc and "on" not in doc:
        problems.append(f"{path}: no 'on' trigger")

    for job_name, job in doc["jobs"].items():
        if not isinstance(job, dict):
            problems.append(f"{path}:{job_name}: job is {type(job).__name__}, expected a mapping")
            continue
        if "runs-on" not in job:
            problems.append(f"{path}:{job_name}: no 'runs-on'")
        steps = job.get("steps")
        if not isinstance(steps, list) or not steps:
            problems.append(f"{path}:{job_name}: no steps")
            continue

        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                problems.append(f"{path}:{job_name}: step {i} is not a mapping")
                continue
            has_uses, has_run = "uses" in step, "run" in step
            if has_uses and has_run:
                problems.append(f"{path}:{job_name}: step {i} has both 'uses' and 'run'")
            if not has_uses and not has_run:
                problems.append(f"{path}:{job_name}: step {i} has neither 'uses' nor 'run'")
            label = step.get("name") or step.get("uses") or f"#{i}"
            if has_run:
                if not isinstance(step["run"], str):
                    problems.append(f"{path}:{job_name}: step {i} 'run' is {type(step['run']).__name__}, expected a string")
                else:
                    check_run_block(f"{path}:{job_name}", i, label, step["run"])


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    files = sorted(
        p for p in list(root.glob(".gitea/workflows/*.yml")) + list(root.glob(".github/workflows/*.yml"))
    )
    if not files:
        print("error: no workflow files found", file=sys.stderr)
        return 1

    for f in files:
        try:
            check_workflow(f)
            print(f"  ✓ {f.relative_to(root)}")
        except Exception as exc:  # a parse error is itself a finding
            problems.append(f"{f}: could not be parsed: {exc}")

    if problems:
        print()
        for p in problems:
            print(f"  ✗ {p}", file=sys.stderr)
        print(f"\n{len(problems)} structural problem(s).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())