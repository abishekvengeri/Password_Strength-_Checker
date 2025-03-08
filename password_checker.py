import re
import math
from getpass import getpass

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = self._load_common_passwords()

    def _load_common_passwords(self):
        # Load list of common passwords (you can add more or use a file)
        return {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password1', 'admin', 'letmein', 'welcome', 'monkey'
        }

    def _calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32

        if charset_size == 0: return 0
        return len(password) * math.log2(charset_size)

    def check_strength(self, password):
        # Initial checks
        if not password:
            return {"strength": "Very Weak", "score": 0, "feedback": "Password is empty"}

        if password.lower() in self.common_passwords:
            return {"strength": "Very Weak", "score": 0, "feedback": "Common password detected"}

        # Criteria scoring
        score = 0
        feedback = []

        # Length
        length = len(password)
        if length >= 8: score += 1
        if length >= 12: score += 2
        if length >= 16: score += 3
        if length < 8:
            feedback.append("Password should be at least 8 characters")

        # Character diversity
        checks = {
            'lower': r'[a-z]',
            'upper': r'[A-Z]',
            'digit': r'[0-9]',
            'special': r'[^a-zA-Z0-9]'
        }

        met_criteria = 0
        for name, pattern in checks.items():
            if re.search(pattern, password):
                met_criteria += 1
                score += 1

        if met_criteria < 3:
            feedback.append("Add more character types (upper/lower case, numbers, symbols)")

        # Entropy calculation
        entropy = self._calculate_entropy(password)
        if entropy < 28:  # ~2^28 guesses needed
            feedback.append("Password is too predictable")
        elif entropy < 50:
            score += 1
        else:
            score += 2

        # Sequential characters check
        if re.search(r'(.)\\1{2}', password):
            score -= 1
            feedback.append("Avoid repeated characters")

        # Final evaluation
        strength_levels = [
            (0, "Very Weak"),
            (3, "Weak"),
            (6, "Moderate"),
            (8, "Strong"),
            (10, "Very Strong")
        ]

        strength = "Very Weak"
        for threshold, level in reversed(strength_levels):
            if score >= threshold:
                strength = level
                break

        return {
            "strength": strength,
            "score": min(score, 10),  # Cap at 10
            "feedback": feedback,
            "entropy": f"{entropy:.1f} bits",
            "length": length
        }

def main():
    checker = PasswordStrengthChecker()

    print("Password Strength Checker")
    print("-------------------------")

    while True:
        try:
            password = getpass("Enter password (or press Ctrl+C to exit): ").strip()
            if not password:
                print("Please enter a password\\n")
                continue

            result = checker.check_strength(password)

            print(f"\\nStrength: {result['strength']}")
            print(f"Score: {result['score']}/10")
            print(f"Length: {result['length']} characters")
            print(f"Entropy: {result['entropy']}")

            if result['feedback']:
                print("\\nRecommendations:")
                for item in result['feedback']:
                    print(f"- {item}")

            print("\\n" + "="*40 + "\\n")

        except KeyboardInterrupt:
            print("\\nExiting...")
            break

if __name__ == "__main__":
    main()
