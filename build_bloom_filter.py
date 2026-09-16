from pybloom_live import BloomFilter

LINE_COUNT = 1012024699  # from count_lines.py

print("Building filter... this reads the whole file once, so it will take a few minutes.")
bf = BloomFilter(capacity=LINE_COUNT, error_rate=0.001)

with open("breachcompilation.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        pw = line.strip()
        if pw:
            bf.add(pw)

with open("breach_bloom.bin", "wb") as f:
    bf.tofile(f)

print("Done! Saved as breach_bloom.bin")