import os, sys
if not os.path.exists("breachcompilation.txt"):
    sys.exit("Needs the real breachcompilation.txt (not included). See README: Full setup with the real datasets.")
count = 0
with open("breachcompilation.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        count += 1
print(f"Total lines: {count:,}")