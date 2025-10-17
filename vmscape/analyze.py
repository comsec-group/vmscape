# SPDX-License-Identifier: GPL-3.0-only
import re
import statistics
import sys
from enum import StrEnum
from pathlib import Path
import os

SCRIPT_DIR = Path(__file__).parent.absolute()

REGEX_EXEC_TIME = r".*real\s+(?P<minutes>\d+)m (?P<seconds>\d+\.\d+)s"
REGEX_ASLR_TIME = r"code_aslr time = (?P<seconds>\d+\.\d+)s"
REGEX_RB_TIME = r"rb_aslr time = (?P<seconds>\d+\.\d+)s"
REGEX_L3_BUILD_TIME = r"l3_build time = (?P<seconds>\d+\.\d+)s"
REGEX_L3_SEARCH_TIME = r"l3_search time = (?P<seconds>\d+\.\d+)s"
REGEX_LEAK_TIME = r"leak_array time = (?P<seconds>\d+\.\d+)s"


# It is very important that the errors are listed in the order in which they appear
class Error(StrEnum):
    ASLR = "Failed to break KASLR!"
    ASLR2 = "Not hitting it right"
    ASLR3 = "Failed to find victim extra offset"
    MEM = "Failed to open /dev/mem"
    HP = "Failed to map 1G"
    HP2 = "Failed to map 1G"
    MAP = "Failed to map snippets"
    MMIO = "Failed to map MMIO"
    RB = "Error getting rb_hva"
    L2 = "Non-unique L2 set match"
    L3 = "Failed to build L3 eviction sets!"
    ES = "Eviction set not found!"
    FILE = "Failed to open output file!"
    PTR = "Failed to retrieve object ptr!"
    OBJ_ROOT = "Failed to retrieve obj_root_ptr"
    OBJ_LEVEL_1 = "Failed to resolve first level of objects"
    OBJ_LEVEL_2 = "Failed to resolve second level of objects"
    SECRET_BUF = "Failed to allocate secret leak array"
    SECRET_LEN = "Failed to retrieve rawlen"
    SECRET_DATA_PTR = "Failed to retrieve rawdata_ptr"
    HT_TABLE = "Failed to retrieve hash_table_ptr"
    HT_KEY_ARRAY = "Failed to retrieve hash_table_key_ptr"
    HT_INVALID_CHOICE = "Invalid object choice"
    HT_VALUE_ARRAY = "Failed to retrieve hash_table_value_ptr"
    HT_VALUE_ENTRY = "Failed to retrieve child_obj_prop_ptr"
    HT_VALUE_RESOLVE = "Failed to retrieve child_obj_ptr"


ERROR_REGEX: dict[Error, str] = {}
ERROR_REGEX[Error.ASLR] = r".*Failed to break code ASLR!.*"
ERROR_REGEX[Error.ASLR2] = r".*Not hitting it right.*"
ERROR_REGEX[Error.ASLR3] = r".*Failed to find victim extra offset.*"
ERROR_REGEX[Error.MEM] = r".*Failed to open /dev/mem.*"
ERROR_REGEX[Error.HP] = r".*Failed to map 1G.*"
ERROR_REGEX[Error.HP2] = r".*mmap 1G page.*"
ERROR_REGEX[Error.MAP] = r".*Failed to map 4096B at.*"
ERROR_REGEX[Error.MMIO] = r".*Failed to map MMIO.*"
ERROR_REGEX[Error.RB] = r".*Error getting rb_hva.*"
ERROR_REGEX[Error.L2] = r".*Non-unique L2 set match.*"
ERROR_REGEX[Error.L3] = r".*Failed to build L3 eviction sets!.*"
ERROR_REGEX[Error.ES] = r".*Eviction set not found!.*"
ERROR_REGEX[Error.FILE] = r".*Failed to open output file.*"
ERROR_REGEX[Error.PTR] = r".*Failed to retrieve object ptr.*"
ERROR_REGEX[Error.OBJ_ROOT] = r".*Failed to retrieve obj_root_ptr.*"
ERROR_REGEX[Error.OBJ_LEVEL_1] = r".*Failed to resolve first level of objects.*"
ERROR_REGEX[Error.OBJ_LEVEL_2] = r".*Failed to resolve second level of objects.*"
ERROR_REGEX[Error.SECRET_BUF] = r".*Failed to allocate secret leak array.*"
ERROR_REGEX[Error.SECRET_LEN] = r".*Failed to retrieve rawlen.*"
ERROR_REGEX[Error.SECRET_DATA_PTR] = r".*Failed to retrieve rawdata_ptr.*"
ERROR_REGEX[Error.HT_TABLE] = r".*Failed to retrieve hash_table_ptr.*"
ERROR_REGEX[Error.HT_KEY_ARRAY] = r".*Failed to retrieve hash_table_key_ptr.*"
ERROR_REGEX[Error.HT_INVALID_CHOICE] = r".*Invalid choice.*"
ERROR_REGEX[Error.HT_VALUE_ARRAY] = r".*Failed to retrieve hash_table_value_ptr.*"
ERROR_REGEX[Error.HT_VALUE_ENTRY] = r".*Failed to retrieve child_obj_prop_ptr.*"
ERROR_REGEX[Error.HT_VALUE_RESOLVE] = r".*Failed to retrieve child_obj_ptr.*"

LEAK_SIZE = 4096


# def has_error(err: dict[Error, int]) -> bool:
#     """Check if any error has happened."""
#     return bool(sum(err.values()))


def secret_diff(path_reference: str, path_guess: str) -> int:
    if not os.path.isfile(path_reference) or not os.path.isfile(path_guess):
        return -1
    matching_count = 0
    with open(path_reference, "rb") as f1:
        with open(path_guess, "rb") as f2:
            data_a = f1.read()
            data_b = f2.read()
            # size_diff = abs(len(data_a) - len(data_b))
            # if size_diff != 0:
            #     print(f"size_diff: {size_diff}")
            for a, b in zip(data_a, data_b):
                # total += 1
                if a == b:
                    matching_count += 1
                # else:
                #     print(f"{total}: {a} != {b}")
    return matching_count


def main():
    files: list[Path] = []

    if len(sys.argv) == 1:
        files = [
            f
            for f in SCRIPT_DIR.iterdir()
            if f.is_file() and f.stem.startswith("run-eval") and f.suffix == ".out"
        ]
        print(f"Reading {len(files)} files from {SCRIPT_DIR}")
    else:
        files = [Path(f) for f in sys.argv[1:]]
        assert all(map(lambda e: e.is_file(), files)), "Not all files exist"
        print(f"Reading {len(files)} files from argument")

    aslr_time_list: list[float] = []
    rb_time_list: list[float] = []
    l3_build_time_list: list[float] = []
    l3_search_time_list: list[float] = []
    leak_time_list: list[float] = []
    success_count_list: list[int] = []
    leak_failed_list: list[bool] = []
    attack_time_list: list[float] = []

    # Number of times we hit a certain error
    num_errors: dict[Error, int] = {}
    for k in Error:
        num_errors[k] = 0

    # check all files in this directory
    for file in files:
        has_error = False
        aslr_time = None
        rb_time = None
        l3_build_time = None
        l3_search_time = None
        leak_time = None
        success_count = None
        leak_failed = False
        attack_time = None
        with open(file, "r", errors="replace") as f:
            # extract interesting data
            for line in f.readlines():
                m = re.match(REGEX_ASLR_TIME, line)
                if m:
                    assert not aslr_time
                    aslr_time = float(m.group("seconds"))
                    continue

                m = re.match(REGEX_EXEC_TIME, line)
                if m:
                    t = (int(m.group("minutes")) * 60) + float(m.group("seconds"))
                    attack_time = t
                    continue

                m = re.match(REGEX_RB_TIME, line)
                if m:
                    assert not rb_time
                    rb_time = float(m.group("seconds"))
                    continue

                m = re.match(REGEX_L3_BUILD_TIME, line)
                if m:
                    assert not l3_build_time
                    l3_build_time = float(m.group("seconds"))
                    continue

                m = re.match(REGEX_L3_SEARCH_TIME, line)
                if m:
                    assert not l3_search_time
                    l3_search_time = float(m.group("seconds"))
                    continue

                m = re.match(REGEX_LEAK_TIME, line)
                if m:
                    assert not leak_time
                    leak_time = float(m.group("seconds"))
                    continue

                for k in Error:
                    m = re.match(ERROR_REGEX[k], line)
                    if m:
                        num_errors[k] += 1
                        print(f"Error {k} in {file.name}")
                        has_error = True
                        break
                else:
                    continue  # If no error, look at next line
                break  # If error, go to next file

            # try to get the diff if there was no error
            if not has_error:
                path_reference = str(file).replace("break.out", "guest-secret.txt")
                path_guess = str(file).replace("break.out", "attack-secret.txt")
                success_count = secret_diff(path_reference, path_guess)
                if (
                    success_count > LEAK_SIZE / 2
                ):  # if there are too many byte errors, we consider the attempt failed
                    print(f"successful file: {file}")
                else:
                    success_count = None
                    leak_failed = True
                    print(f"leak failed file: {file}")

        if aslr_time:
            aslr_time_list.append(aslr_time)
        if rb_time:
            rb_time_list.append(rb_time)
        if l3_build_time:
            l3_build_time_list.append(l3_build_time)
        if l3_search_time:
            l3_search_time_list.append(l3_search_time)
        if leak_time:
            leak_time_list.append(leak_time)
        if success_count:
            success_count_list.append(success_count)
        leak_failed_list.append(leak_failed)
        if attack_time:
            attack_time_list.append(attack_time)

    print(f"aslr_time_list: {aslr_time_list}")
    print(f"rb_time_list: {rb_time_list}")
    print(f"l3_build_time_list: {l3_build_time_list}")
    print(f"l3_search_time_list: {l3_search_time_list}")
    print(f"leak_time_list: {leak_time_list}")
    print(f"success_count_list: {success_count_list}")
    print(f"leak_failed_list: {leak_failed_list}")
    print(f"attack_time_list: {attack_time_list}")

    print(f"Repetitions: {len(files)}")

    print(f"{10 * '='} ERROR STATS {10 * '='}")

    num_valid = len(files)
    for k in Error:
        num_error = num_errors[k]
        print(f"{k}: {num_error} / {num_valid} ({num_error / num_valid * 100:.2f}%)")
        num_valid -= num_error
        # also subtract the very bad leaks

    num_error = sum(leak_failed_list)
    print(
        f"Failed to leak useful: {num_error} / {num_valid} ({num_error / num_valid * 100:.2f}%)"
    )
    num_valid -= num_error

    print(
        f"Overall success rate: {num_valid} / {len(files)} ({num_valid / len(files) * 100:.2f}%)"
    )

    # calculate the median value for each
    aslr_time_median = round(statistics.median(aslr_time_list))
    rb_time_median = round(statistics.median(rb_time_list))
    # l3_build_time_median = round(statistics.median(l3_build_time_list))
    # l3_search_time_median = round(statistics.median(l3_search_time_list))
    # leak_time_median = round(statistics.median(leak_time_list))
    leak_rate_median = round(statistics.median([LEAK_SIZE / t for t in leak_time_list]))
    success_count_median = round(statistics.median(success_count_list))
    attack_time_median = round(statistics.median(attack_time_list))
    end_to_end_median = round(
        statistics.median([a + b for a, b in zip(aslr_time_list, attack_time_list)])
    )

    print(f"{10 * '='} TIMING STATS {10 * '='}")
    print(f"ASLR Break Median Time: {aslr_time_median}s")
    print(f"RB Search Median Time: {rb_time_median}s")
    print(f"Leak Rate Median: {leak_rate_median}B/s")
    print(f"End-to-end Median Time: {end_to_end_median}s")
    print(f"End-to-end Median Time2: {aslr_time_median + attack_time_median}s")

    print(f"{10 * '='} CHANNEL STATS {10 * '='}")
    print(f"Channel accuracy: {success_count_median / LEAK_SIZE * 100:.2f}%")


if __name__ == "__main__":
    main()
