count = 0
with open("breachcompilation.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        count += 1
print(f"Total lines: {count:,}")