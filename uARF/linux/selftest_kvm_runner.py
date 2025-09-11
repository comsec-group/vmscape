#!/bin/env python

"""
Runner script for the guest bti experiment
"""

import argparse
import itertools
import os
import platform
import subprocess
import sys
from enum import Enum
from pathlib import Path

CWD = Path(__file__)

UARF_PATH: Path = Path(os.environ.get("UARF_PATH", Path.home() / "uARF"))
LINUX_PATH: Path = Path(
    os.environ.get("LINUX_PATH", Path.home() / "LinuxKernelTorvalds")
)

TEST_EXEC_PATH = LINUX_PATH / "tools/testing/selftests/kvm/x86_64/rev_eng/exp_guest_bti"

DATA_PATH: Path = UARF_PATH / "data"

if not UARF_PATH.is_dir():
    print(f"Uarf repo does not exist at '{UARF_PATH}'")

if not LINUX_PATH.is_dir():
    print(f"Linux repo does not exist at '{LINUX_PATH}'")

if not TEST_EXEC_PATH.is_file():
    print(f"Test does not exist at '{TEST_EXEC_PATH}'")


class Domain(Enum):
    """Represents the domain of a virtualized environment."""

    HU = "HU"
    HS = "HS"
    GU = "GU"
    GS = "GS"


# Number of iteration that we let the test run at one. Should not be too large as the results of a full back are lost when one iteration fails
BATCH_RERAND_SIZE = 10


class Config:
    """
    A single configuration to be tested.

    Attributes:
        host: Hostname of the system on this this getting executed.
        td: Training domain.
        sd: Signaling domain.
        num_measures: Total number of measures to take.
        num_cands: Number of times the addresses get rerandomized over `num_measures`.
        reps_per_cand: Number of measures per candidate.
        cand_batch: How many candidates are batched together (all lost upon excaption of test).
        num_training: Number of training iterations, 0 for false positive test.
    """

    host: str
    td: Domain
    sd: Domain
    num_measures: int
    num_cands: int
    reps_per_cand: int
    cand_batch: int
    autoibrs_on: bool  # TODO: make more generic
    fp_test: bool
    fn_test: bool
    use_jmp: bool

    def __init__(
        self,
        td: Domain,
        sd: Domain,
        num_measures: int,
        rerand_after: int,
        use_jmp: bool,
        fp_test: bool,
        fn_test: bool,
    ) -> None:
        assert (
            num_measures % rerand_after == 0
        ), "rerand_after should divide num_measures"

        self.host = platform.node().removeprefix("ee-tik-")
        self.td = td
        self.sd = sd
        self.num_measures = num_measures
        self.num_cands = num_measures // rerand_after
        self.reps_per_cand = rerand_after
        self.cand_batch = BATCH_RERAND_SIZE
        self.autoibrs_on = True
        self.fp_test = fp_test
        self.fn_test = fn_test
        self.use_jmp = use_jmp

        assert (
            self.num_cands % self.cand_batch == 0
        ), "number of batched candidates should divide the total number of candidates"

    def __str__(self) -> str:
        return (
            f"{self.host}__"
            f"{self.td.value}_{self.sd.value}__"
            f"{self.num_cands}__"
            f"{self.reps_per_cand}__"
            f"{'jmp' if self.use_jmp else 'call'}"
            f"{'__fp' if self.fp_test else ''}"
            f"{'__fn' if self.fn_test else ''}"
        )

    def identifier(self) -> str:
        """
        Represent the exact configuration.
        """
        return str(self)


# ===== START CONFIG ===== #
NUM_MEAS = 10000
RERAND_BATCH = 10

_cfgs: list[list[Config]] = [
    [Config(d, Domain.GS, NUM_MEAS, RERAND_BATCH, False, False, False) for d in Domain],
    [Config(d, Domain.GS, NUM_MEAS, RERAND_BATCH, False, True, False) for d in Domain],
    [Config(d, Domain.GS, NUM_MEAS, RERAND_BATCH, False, False, True) for d in Domain],
    [Config(d, Domain.GS, NUM_MEAS, RERAND_BATCH, True, False, False) for d in Domain],
    [Config(d, Domain.GS, NUM_MEAS, RERAND_BATCH, True, True, False) for d in Domain],
    [Config(d, Domain.GS, NUM_MEAS, RERAND_BATCH, True, False, True) for d in Domain],
    # # Use ind. Call
    # [Config(Domain.HU, d, NUM_MEAS, RERAND_BATCH, False, False, False) for d in Domain],
    # [Config(Domain.HS, d, NUM_MEAS, RERAND_BATCH, False, False, False) for d in Domain],
    # [Config(Domain.GU, d, NUM_MEAS, RERAND_BATCH, False, False, False) for d in Domain],
    # [Config(Domain.GS, d, NUM_MEAS, RERAND_BATCH, False, False, False) for d in Domain],
    # # Use ind. Jump
    # [Config(Domain.HU, d, NUM_MEAS, RERAND_BATCH, True, False, False) for d in Domain],
    # [Config(Domain.HS, d, NUM_MEAS, RERAND_BATCH, True, False, False) for d in Domain],
    # [Config(Domain.GU, d, NUM_MEAS, RERAND_BATCH, True, False, False) for d in Domain],
    # [Config(Domain.GS, d, NUM_MEAS, RERAND_BATCH, True, False, False) for d in Domain],
    # # FP for Call
    # [Config(Domain.HU, d, 1000, RERAND_BATCH, False, True, False) for d in Domain],
    # [Config(Domain.HS, d, 1000, RERAND_BATCH, False, True, False) for d in Domain],
    # [Config(Domain.GU, d, 1000, RERAND_BATCH, False, True, False) for d in Domain],
    # [Config(Domain.GS, d, 1000, RERAND_BATCH, False, True, False) for d in Domain],
    # # FN for Call
    # [Config(Domain.HU, d, 1000, RERAND_BATCH, False, False, True) for d in Domain],
    # [Config(Domain.HS, d, 1000, RERAND_BATCH, False, False, True) for d in Domain],
    # [Config(Domain.GU, d, 1000, RERAND_BATCH, False, False, True) for d in Domain],
    # [Config(Domain.GS, d, 1000, RERAND_BATCH, False, False, True) for d in Domain],
]

cfgs = list(itertools.chain.from_iterable(_cfgs))
# =====  End CONFIG  ===== #


def run_config(cfg: Config, args: argparse.Namespace, out_dir: Path) -> None:
    raw_out_file = out_dir / (cfg.identifier() + ".raw")
    cmp_out_file = out_dir / (cfg.identifier() + ".cmp")

    print(f"Running config {cfg.identifier()}:\n")
    out_dir.mkdir(parents=True, exist_ok=True)

    if raw_out_file.exists():
        assert raw_out_file.is_file()

        if args.force:
            print("Previous output exists. Removing")
            raw_out_file.unlink()
            cmp_out_file.unlink(missing_ok=True)
        elif args.resume:
            print("Previous output exists. Resuming")
            raise NotImplementedError
        else:
            print("Previous results exists. Nothing to do.")
            return

    # Holds all the raw output lines
    raw_accum: str = ""

    hit_accum = 0
    n_accum = 0

    print("Iteration: ", end="", flush=True)

    # The executable can segfault, number of successful runs
    succ_iter = 0
    while succ_iter < cfg.num_cands:
        print(f"{succ_iter}, ", end="", flush=True)
        cmd = [
            str(TEST_EXEC_PATH),
            "-t",
            cfg.td.value,
            "-s",
            cfg.sd.value,
            "-c",
            f"{cfg.cand_batch}",
            "-r",
            f"{cfg.reps_per_cand}",
            f"{'-p' if cfg.fp_test else ''}",
            f"{'-n' if cfg.fn_test else ''}",
            f"{'-j' if cfg.use_jmp else ''}",
            "-e",
        ]

        # print(f"Running {' '.join(cmd)}")

        try:
            res = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            # Segfault if something with the random allocation does not work
            if e.returncode == -11:
                print("!", end="", flush=True)
                continue
            # General runtime error
            # Just repeat
            if e.returncode == 1:
                print("!", end="", flush=True)
                continue
            # Invalid Argument
            if e.returncode == 2:
                print(f"Invalid argument: {e}")
                print(e.stdout)
                print(e.stderr)
                sys.exit(1)
            # VM Error
            # Just pray and repeat
            if e.returncode == 3:
                print("?", end="", flush=True)
                continue

            print(f"Unknown error: {e}")
            print(e.stdout)
            print(e.stderr)
            sys.exit(1)

        out = res.stdout

        if args.dry_run:
            print(f"\n{out}")

        for line in out.splitlines():
            parts = line.split("\t")
            assert len(parts) == 2, f"invalid output: {parts}"
            hits, total = map(int, parts)
            hit_accum += hits
            n_accum += total

        raw_accum += out
        succ_iter += cfg.cand_batch

    print("")

    assert n_accum == cfg.num_measures

    if args.dry_run:
        print(f"total hist: {hit_accum} of: {n_accum}")
    else:
        with open(raw_out_file, "w") as f:
            f.write(raw_accum)

        with open(cmp_out_file, "w") as f:
            f.write(f"{hit_accum}\t{n_accum}")


if __name__ == "__main__":
    print("Starting")
    print("!!! We assume the setup has been done, without any further verification !!!")

    parser = argparse.ArgumentParser(
        prog="Crossdomain BTI Runner",
        description="Run the crossdomain BTI experiment and collect results.",
    )

    parser.add_argument(
        "-f", "--force", action="store_true", help="Overwrite previous results."
    )
    parser.add_argument(
        "-r",
        "--resume",
        action="store_true",
        help="Resume previous results if incomplete.",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="Do not write output to file but print to STDOUT.",
    )

    args = parser.parse_args()

    for cfg in cfgs:
        run_config(cfg, args, DATA_PATH)
