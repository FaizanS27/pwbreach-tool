import csv

new_password = "890333665189мшл"

with open("test_passwords.csv", "a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([new_password, "found_breachcompilation_only"])

print("Added successfully.")