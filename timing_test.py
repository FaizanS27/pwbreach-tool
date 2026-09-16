from engine import in_breach_compilation
import time

test_password = input("Enter a password to time: ")

print("Checking... this may take a few minutes for a large file.")
start = time.perf_counter()
found = in_breach_compilation(test_password)
end = time.perf_counter()

elapsed_seconds = end - start
minutes = int(elapsed_seconds // 60)
seconds = elapsed_seconds % 60

print(f"\nPassword: {test_password}")
print(f"Found in BreachCompilation: {found}")
print(f"Time taken: {minutes} min {seconds:.1f} sec  ({elapsed_seconds:.2f} total seconds)")