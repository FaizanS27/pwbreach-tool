import csv
from baseline_checker import check_password_baseline
from engine import full_check, load_dictionary

print("Loading dictionary...")
dictionary_hashes = load_dictionary()

with open("test_passwords.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    passwords = [row["password"] for row in reader]

print(f"\n{'PASSWORD':<32} {'BASELINE':<12} {'INTEGRATED VERDICT':<28} {'CAUGHT ONLY BY INTEGRATED?'}")
print("-" * 100)

caught_only_by_integrated = 0

for pw in passwords:
    baseline_result = check_password_baseline(pw)
    baseline_label = "FLAGGED" if baseline_result > 0 else "clean"

    integrated_result = full_check(pw, dictionary_hashes)
    integrated_label = integrated_result["verdict"]

    only_integrated = (baseline_label == "clean") and (integrated_label != "STRONG")
    if only_integrated:
        caught_only_by_integrated += 1

    print(f"{pw:<32} {baseline_label:<12} {integrated_label:<28} {'YES' if only_integrated else 'no'}")

print("-" * 100)
print(f"\nOut of {len(passwords)} passwords tested, the integrated tool caught "
      f"{caught_only_by_integrated} weak/risky password(s) that the breach-only baseline missed entirely.")