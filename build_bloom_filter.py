"""
Builds the Bloom filter used for the BreachCompilation check.

Usage:
    python build_bloom_filter.py                      # full dataset (breachcompilation.txt -> breach_bloom.bin)
    python build_bloom_filter.py INPUT.txt OUTPUT.bin # any wordlist, e.g. the demo data in data/
    python build_bloom_filter.py INPUT.txt OUTPUT.bin --capacity 5000

The input is one password per line (UTF-8). If --capacity is not given, it is
the known line count for the full BreachCompilation file, or counted from the
input file for any other input.
"""
import argparse
from pybloom_live import BloomFilter

FULL_INPUT = "breachcompilation.txt"
FULL_OUTPUT = "breach_bloom.bin"
FULL_LINE_COUNT = 1012024699  # produced by count_lines.py on the full file
ERROR_RATE = 0.001            # ~1 in 1000 false positives; never any false negatives

parser = argparse.ArgumentParser(description="Build the BreachCompilation Bloom filter.")
parser.add_argument("input", nargs="?", default=FULL_INPUT)
parser.add_argument("output", nargs="?", default=FULL_OUTPUT)
parser.add_argument("--capacity", type=int, default=None)
args = parser.parse_args()

capacity = args.capacity
if capacity is None:
    if args.input == FULL_INPUT:
        capacity = FULL_LINE_COUNT
    else:
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            capacity = max(sum(1 for _ in f), 1)

print(f"Building filter from {args.input} (capacity {capacity:,}). "
      f"The full ~10 GB file reads once and takes several hours.")
bf = BloomFilter(capacity=capacity, error_rate=ERROR_RATE)

with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        pw = line.strip()
        if pw:
            bf.add(pw)

with open(args.output, "wb") as f:
    bf.tofile(f)

print(f"Done! Saved as {args.output}")
