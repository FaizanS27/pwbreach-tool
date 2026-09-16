from engine import in_breach_compilation
import time

# A few passwords taken directly from your real sample data
test_cases = [
    "teamochapa",
    "cfvjqkjdrf105",
    "brantner1",
    "nshmotherlode",
    "nikoz581",
    "kbvgjgj",
    "this-should-not-exist-anywhere-xyz123",  # should be False
]

for pw in test_cases:
    start = time.perf_counter()
    found = in_breach_compilation(pw)
    elapsed = time.perf_counter() - start
    print(f"{pw:<40} found={found}   ({elapsed:.3f}s)")