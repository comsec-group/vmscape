#!/bin/env python

import sys
from termcolor import colored


def highlight_bits(address: int) -> None:
    # Convert the address to a 64-bit binary string
    binary_address = f"{address:064b}"

    # Bit segment lengths
    cache_line_offset_len = 6
    l1_index_len = 9
    l2_index_len = 12
    l3_index_len = 15
    page_offset_len = 12

    # Calculate starting positions for each segment
    page_offset_start = 64 - page_offset_len
    l3_index_start = page_offset_start - l3_index_len
    l2_index_start = l3_index_start - l2_index_len
    l1_index_start = l2_index_start - l1_index_len
    cache_line_offset_start = l1_index_start - cache_line_offset_len

    # Create the underlines
    underline = (
        "\033[31m"
        + "‾" * cache_line_offset_len
        + "\033[0m"
        + "\033[33m"
        + "‾" * l1_index_len
        + "\033[0m"
        + "\033[32m"
        + "‾" * l2_index_len
        + "\033[0m"
        + "\033[34m"
        + "‾" * l3_index_len
        + "\033[0m"
        + "\033[35m"
        + "‾" * page_offset_len
        + "\033[0m"
    )

    pages = (
        colored(f"[{'sign extend':^14}]", "blue")
        + colored(f"[{'PML4':^7}]", "blue")
        + colored(f"[{'PDP':^7}]", "blue")
        + colored(f"[{'PD':^7}]", "blue")
        + colored(f"[{'PT':^7}]", "blue")
        + colored(f"[{'Offset':^10}]", "red")
    )

    l1 = colored(f"{' ':>52}[{'L1':^4}]", "red")
    l2 = colored(f"{' ':>47}[{'L2':^9}]", "red")
    l3 = colored(f"{' ':>43}[{'L3':^13}]", "red")

    # Print the highlighted binary string
    print(f"Address: 0x{address:x}")
    print(f"           " + "".join((str(i % 10) for i in range(63, -1, -1))))
    print(f"           " + pages)
    print(f"Binary:  0b{binary_address}")
    print(f"           " + l1)
    print(f"           " + l2)
    print(f"           " + l3)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python cache_bit_highlighter.py <hex_address>")
        sys.exit(1)

    try:
        address = int(sys.argv[1], 16)  # Interpret the input as hexadecimal
    except ValueError:
        print("Invalid address. Please enter a valid hexadecimal number.")
        sys.exit(1)

    highlight_bits(address)
