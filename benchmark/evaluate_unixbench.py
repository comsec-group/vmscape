#!/usr/bin/env python

import re
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


def get_scores(p: Path) -> list[float]:
    """Open UnixBench output at p and returns all scores."""
    assert p.is_file()

    with open(p, "r") as f:
        data = f.read()
        pattern = re.compile(
            r"^\s*.*?\s+\d+\.\d+\s+\d+\.\d+\s+([\d\.]+)\s*$", re.MULTILINE
        )

        # Extract all INDEX values
        index_values = [float(match) for match in pattern.findall(data)]
        assert len(index_values) == 12, "Reading scores from file somehow failed"

        return index_values


# Calculate the geometric mean over all test execution for a single run
baseline_score = statistics.geometric_mean(get_scores(baseline_file))
mitigation_score = statistics.geometric_mean(get_scores(mitigation_file))


def get_overhead(baseline: float, mitigation: float) -> float:
    """Calculate the overhead.

    The formulat may look weird at first. This is because unixbench has variable work, but fixed execution time.
    """
    return ((baseline / mitigation) - 1) * 100


overhead = get_overhead(baseline_score, mitigation_score)

print(f"Overhead {overhead:.2f}%")
