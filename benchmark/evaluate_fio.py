#!/usr/bin/env python

import json
import statistics
import sys
from pathlib import Path

if len(sys.argv) != 3:
    print(f"Invalid invocation. Use '{sys.argv[0]} BASELINE_PATH MITIGATION_PATH'")
    sys.exit(1)

baseline_file = Path(sys.argv[1])
assert baseline_file.is_file(), "Not an existing file"

mitigation_file = Path(sys.argv[2])
assert mitigation_file.is_file(), "Not an existing file"


def get_runtimes(p: Path) -> list[int]:
    """Open json at p and return all 'job_runtime'."""
    assert p.is_file()

    with open(p, "r") as f:
        data = json.load(f)

        # print(data['jobs'])
        return [int(e["job_runtime"]) for e in data["jobs"]]


# Calculate the geometric mean over all runs
baseline_runtime = statistics.geometric_mean(get_runtimes(baseline_file))
mitigation_runtime = statistics.geometric_mean(get_runtimes(mitigation_file))


def get_overhead(baseline: float, mitigation: float) -> float:
    """Calculate the overhead."""
    return (mitigation - baseline) / baseline * 100


overhead = get_overhead(baseline_runtime, mitigation_runtime)

print(f"Overhead {overhead:.2f}%")
