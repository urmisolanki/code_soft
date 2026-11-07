
import re
import getpass

print("=" * 40)
print("     PASSWORD STRENGTH CHECKER")
print("=" * 40)

password = getpass.getpass("Enter a password to check: ")

score = 0
suggestions = []

# Check password length
if len(password) >= 12:
    score += 1
else:
    suggestions.append("Use at least 12 characters.")

# Check uppercase letters
if re.search(r"[A-Z]", password):
    score += 1
else:
    suggestions.append("Add an uppercase letter (A-Z).")

# Check lowercase letters
if re.search(r"[a-z]", password):
    score += 1
else:
    suggestions.append("Add a lowercase letter (a-z).")

# Check numbers
if re.search(r"[0-9]", password):
    score += 1
else:
    suggestions.append("Add a number (0-9).")

# Check special characters
if re.search(r"[^A-Za-z0-9]", password):
    score += 1
else:
    suggestions.append("Add a special character, such as ! or @.")

# Display result
print("\n" + "=" * 40)
print("PASSWORD ANALYSIS")
print("=" * 40)

print("Criteria passed:", score, "/ 5")

if score <= 2:
    print("Strength: WEAK")
elif score <= 4:
    print("Strength: MODERATE")
else:
    print("Strength: STRONG")

if suggestions:
    print("\nSuggestions to improve your password:")
    for suggestion in suggestions:
        print("-", suggestion)
else:
    print("\nAll basic checks passed!")

print("\nImportant:")
print("This is a basic educational checker.")
print("It does not guarantee password security.")
print("Never share your real password.")
print("=" * 40)
