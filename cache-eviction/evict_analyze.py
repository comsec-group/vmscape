import os

SCRIPT_DIR = os.path.realpath(os.path.dirname(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")


def parse_file(file_path):
    with open(file_path) as f:
        for line in f.readlines():
            if "All L3 sets work" in line:
                return True
    return False


def eval_mode(mode):
    total_count = 0
    success_count = 0
    for f in os.listdir(DATA_DIR):
        if f.startswith(f"run-evict-{mode}") and f.endswith(".out"):
            file_path = os.path.join(DATA_DIR, f)
            total_count += 1
            res = parse_file(file_path)
            if res:
                success_count += 1
    print(
        f"{mode}: {success_count}/{total_count} ({round(100 * success_count / total_count, 1)}%)"
    )


def main():
    eval_mode("vm")
    eval_mode("native")


if __name__ == "__main__":
    main()
