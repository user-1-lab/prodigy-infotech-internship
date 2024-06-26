# Password Strength checker

import re

class PasswordStrengthChecker:
    def __init__(self, password):
        self.password = password
        self.strength_criteria = {
            'length': False,
            'uppercase': False,
            'lowercase': False,
            'numbers': False,
            'special_characters': False
        }
        self.overall_strength = 'Unknown'

    def check_length(self):
        if len(self.password) >= 8:
            self.strength_criteria['length'] = True

    def check_uppercase(self):
        if re.search('[A-Z]', self.password):
            self.strength_criteria['uppercase'] = True

    def check_lowercase(self):
        if re.search('[a-z]', self.password):
            self.strength_criteria['lowercase'] = True

    def check_numbers(self):
        if re.search('[0-9]', self.password):
            self.strength_criteria['numbers'] = True

    def check_special_characters(self):
        if re.search(r'[^a-zA-Z0-9]', self.password):
            self.strength_criteria['special_characters'] = True 

    def calculate_overall_strength(self):
        strength_score = 0
        for criterion, value in self.strength_criteria.items():
            if value:
                strength_score += 1

        if strength_score == 5:
            self.overall_strength = 'Strong'
        elif strength_score >= 3:
            self.overall_strength = 'Medium'
        else:
            self.overall_strength = 'Weak'

    def print_results(self):
        print("Password Strength Check:")
        for criterion, value in self.strength_criteria.items():
            print(f"{criterion.title()}: {value}")
        print(f"Overall Strength: {self.overall_strength}")

def main():
    password = input("Enter a password: ")
    checker = PasswordStrengthChecker(password)
    checker.check_length()
    checker.check_uppercase()
    checker.check_lowercase()
    checker.check_numbers()
    checker.check_special_characters()
    checker.calculate_overall_strength()
    checker.print_results()

if __name__ == "__main__":
    main()
