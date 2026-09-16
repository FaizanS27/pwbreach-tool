import hashlib
import requests

def check_password_baseline(password):
    """
    Check if a password has appeared in the Have I Been Pwned database.
    """

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    response = requests.get(url, headers={"Add-Padding": "true"})

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0


if __name__ == "__main__":
    password = input("Enter a password: ")

    result = check_password_baseline(password)

    if result == 0:
        print("✅ Password NOT found in any known breach.")
    else:
        print(f"❌ Password found {result:,} times in known breaches.")
        