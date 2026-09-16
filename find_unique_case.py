from baseline_checker import check_password_baseline
import random
import re

def looks_like_a_hash(pw):
    """Filters out entries that look like MD5/SHA hashes rather than real passwords."""
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", pw)) or \
           bool(re.fullmatch(r"[0-9a-fA-F]{40}", pw)) or \
           bool(re.fullmatch(r"[0-9a-fA-F]{64}", pw))

print("Reading random lines from breachcompilation.txt to search for a case")
print("that's in BreachCompilation but NOT in HIBP (excluding hash-looking strings)...\n")

candidates = []
with open("breachcompilation.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        pw = line.strip()
        if pw and 6 <= len(pw) <= 20 and not looks_like_a_hash(pw):
            candidates.append(pw)
        if len(candidates) >= 2000:
            break

random.shuffle(candidates)

found_example = None
checked = 0

for pw in candidates:
    checked += 1
    breach_count = check_password_baseline(pw)
    if breach_count == 0:
        found_example = pw
        break
    if checked % 50 == 0:
        print(f"Checked {checked} so far, still searching...")

print("\n---RESULT---")
if found_example:
    print(f"Found one: '{found_example}' is in BreachCompilation but NOT in HIBP.")
else:
    print(f"Checked {checked} realistic-looking passwords - all were already in HIBP too.")