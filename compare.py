import csv
import sys
from zxcvbn import zxcvbn
from baseline_checker import check_password_baseline
from engine import full_check, load_dictionary

# Print Cyrillic and other non-English passwords correctly, also when output is redirected.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

print("Loading dictionary...")
dictionary_hashes = load_dictionary()

with open("test_passwords.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    passwords = [row["password"] for row in reader]

print(f"\n{'PASSWORD':<30} {'HIBP-ONLY':<10} {'ZXCVBN-ONLY':<13} {'INTEGRATED VERDICT':<28} {'ONLY INTEGRATED vs HIBP?':<26} {'vs ZXCVBN?'}")
print("-" * 125)

n = len(passwords)
hibp_flagged = zxcvbn_weak = integrated_flagged = 0
breached_total = breached_missed_by_zxcvbn = 0
only_vs_hibp = only_vs_zxcvbn = 0

for pw in passwords:
    hibp_result = check_password_baseline(pw)
    hibp_label = "FLAGGED" if hibp_result > 0 else "clean"

    z_score = zxcvbn(pw)["score"]
    z_label = f"weak ({z_score})" if z_score < 3 else f"ok ({z_score})"

    verdict = full_check(pw, dictionary_hashes)["verdict"]
    is_breached = verdict in ("COMPROMISED", "WEAK - COMMON PASSWORD")

    vs_hibp = (hibp_label == "clean") and (verdict != "STRONG")
    vs_zxcvbn = (z_score >= 3) and (verdict != "STRONG")

    hibp_flagged += hibp_label == "FLAGGED"
    zxcvbn_weak += z_score < 3
    integrated_flagged += verdict != "STRONG"
    breached_total += is_breached
    breached_missed_by_zxcvbn += is_breached and z_score >= 3
    only_vs_hibp += vs_hibp
    only_vs_zxcvbn += vs_zxcvbn

    print(f"{pw:<30} {hibp_label:<10} {z_label:<13} {verdict:<28} {'YES' if vs_hibp else 'no':<26} {'YES' if vs_zxcvbn else 'no'}")

print("-" * 125)
print(f"\nPasswords tested:                         {n}")
print(f"Flagged by HIBP alone:                    {hibp_flagged}")
print(f"Rated weak by zxcvbn alone (score < 3):   {zxcvbn_weak}")
print(f"Flagged by the integrated tool:           {integrated_flagged}")
print(f"Known-breached/common (integrated):       {breached_total}")
print(f"  ...of which zxcvbn alone rates OK:      {breached_missed_by_zxcvbn}")
print(f"Caught only by integrated vs HIBP-only:   {only_vs_hibp}")
print(f"Caught only by integrated vs zxcvbn-only: {only_vs_zxcvbn}")
