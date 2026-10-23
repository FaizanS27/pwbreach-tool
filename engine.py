import os
import math
import hashlib
import secrets
import string
from collections import Counter
from zxcvbn import zxcvbn
from pybloom_live import BloomFilter
from baseline_checker import check_password_baseline


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_DICT = os.path.join(BASE_DIR, "data", "sample_common_passwords.txt")
DEMO_BLOOM = os.path.join(BASE_DIR, "data", "demo_breach_bloom.bin")


def _resolve(primary, demo, label):
    """
    Use the real dataset if it is present (current folder or repo folder).
    Otherwise fall back to the small demo data shipped in data/ so the
    project can be run and reviewed without the multi-GB datasets.
    """
    for candidate in (primary, os.path.join(BASE_DIR, primary)):
        if os.path.exists(candidate):
            return candidate, False
    print(f"[DEMO MODE] {primary} not found - using small demo {label} from data/. "
          f"Results for the {label} check are NOT representative.")
    return demo, True


def shannon_entropy(password):
    """
    Measures how 'random-looking' a password is, in bits.
    Higher = more unpredictable.
    """
    if not password:
        return 0.0
    frequency = Counter(password)
    length = len(password)
    entropy = 0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy * length


def check_zxcvbn(password):
    """Uses the zxcvbn library to realistically estimate crackability."""
    result = zxcvbn(password)
    crack_time = result["crack_times_display"].get(
        "offline_slow_hashing_1e4_per_second", "unknown"
    )
    return {
        "score": result["score"],  # 0 (terrible) to 4 (great)
        "suggestions": result["feedback"].get("suggestions", []),
        "crack_time_display": crack_time,
    }


def load_dictionary(filepath=None):
    """
    Loads the smaller RockYou password list fully into memory as hashes,
    so checking against it is instant. This works fine for RockYou
    because it's small enough (~14 million lines) to fit in RAM.
    """
    if filepath is None:
        filepath, _ = _resolve("rockyou.txt", DEMO_DICT, "dictionary")
    hashes = set()
    with open(filepath, "r", encoding="latin-1", errors="ignore") as f:
        for line in f:
            pw = line.strip()
            if pw:
                hashes.add(hashlib.sha1(pw.encode()).hexdigest().upper())
    return hashes


def in_rockyou(password, hash_set):
    """Fast, in-memory check against the RockYou hash set."""
    return hashlib.sha1(password.encode()).hexdigest().upper() in hash_set


# Load the Bloom filter once, when this file is first imported/run.
# This is fast even though the original file was 10GB, because the
# filter itself (breach_bloom.bin) is a much smaller, pre-built summary.
print("Loading BreachCompilation Bloom filter...")
BLOOM_PATH, DEMO_MODE = _resolve("breach_bloom.bin", DEMO_BLOOM, "Bloom filter")
with open(BLOOM_PATH, "rb") as f:
    breach_bloom_filter = BloomFilter.fromfile(f)
print("Bloom filter loaded. Ready.")


def in_breach_compilation(password):
    """
    Checks the password against the pre-built Bloom filter instead of
    scanning the original 10GB file directly. Lookups are now
    near-instant (milliseconds instead of minutes).
    Note: extremely rare false positives are possible (~0.1% chance),
    but it will never miss a password that's genuinely in the file.
    """
    return password in breach_bloom_filter


def generate_strong_password(length=16):
    """Creates a random, strong password suggestion when the checked one is weak."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def full_check(password, dictionary_hashes):
    """
    The integrated check: combines all checks into one final verdict.
    Order matters here - HIBP (fast) is checked first. If it already
    finds a breach, that's automatically the worst-case result, so we
    skip the dictionary/Bloom filter checks entirely to save time.
    """
    entropy = shannon_entropy(password)
    pattern_result = check_zxcvbn(password)
    breach_count = check_password_baseline(password)

    # Status of each of the five checks, including the ones skipped because an
    # earlier check already settled the verdict. Used by the report-card view.
    checks = {
        "entropy": {"checked": True, "status": "info", "value": round(entropy, 2)},
        "pattern": {
            "checked": True,
            "status": "pass" if pattern_result["score"] >= 3 else "fail",
            "value": pattern_result["score"],
        },
        "hibp": {
            "checked": True,
            "status": "fail" if breach_count > 0 else "pass",
            "value": breach_count,
        },
        "rockyou": {"checked": False, "status": "skipped", "value": None},
        "breachcompilation": {"checked": False, "status": "skipped", "value": None},
    }

    dict_hit = None  # None = not checked (already breached)

    if breach_count > 0:
        verdict = "COMPROMISED"
        message = f"This exact password has appeared in {breach_count:,} known breaches. Change it completely."

    else:
        # Only check RockYou + BreachCompilation if HIBP didn't already flag it.
        rockyou_hit = in_rockyou(password, dictionary_hashes)
        checks["rockyou"] = {
            "checked": True,
            "status": "fail" if rockyou_hit else "pass",
            "value": rockyou_hit,
        }
        if rockyou_hit:
            dict_hit = True  # Bloom filter skipped: RockYou already found a match
        else:
            bc_hit = in_breach_compilation(password)
            checks["breachcompilation"] = {
                "checked": True,
                "status": "fail" if bc_hit else "pass",
                "value": bc_hit,
            }
            dict_hit = bc_hit

        if dict_hit:
            verdict = "WEAK - COMMON PASSWORD"
            message = "This password is in a known leaked password list."
        elif pattern_result["score"] < 3:
            verdict = "WEAK - PREDICTABLE PATTERN"
            suggestion = pattern_result["suggestions"][0] if pattern_result["suggestions"] else "Try adding an unrelated word."
            message = suggestion
        else:
            verdict = "STRONG"
            message = "No issues found across structure or breach checks."

    suggested_password = generate_strong_password() if verdict != "STRONG" else None

    return {
        "password": password,
        "entropy_bits": round(entropy, 2),
        "zxcvbn_score": pattern_result["score"],
        "crack_time_display": pattern_result["crack_time_display"],
        "in_common_list": dict_hit,
        "hibp_breach_count": breach_count,
        "checks": checks,
        "verdict": verdict,
        "message": message,
        "suggested_password": suggested_password,
    }


# Quick manual test - only runs when you execute this file directly
if __name__ == "__main__":
    print("Loading RockYou dictionary...")
    dictionary_hashes = load_dictionary()
    print(f"Loaded {len(dictionary_hashes):,} known passwords from RockYou.\n")

    test_password = input("Enter a password to check: ")
    result = full_check(test_password, dictionary_hashes)
    print("\n========== RESULT ==========")
    for key, value in result.items():
        print(f"{key}: {value}")