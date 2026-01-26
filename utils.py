import random
import string


def generate_card_number():
    """Generate a 16-digit card number"""
    # Vulnerability: Predictable card number generation
    return ''.join(random.choices(string.digits, k=16))

def generate_cvv():
    """Generate a 3-digit CVV"""
    # Vulnerability: Predictable CVV generation
    return ''.join(random.choices(string.digits, k=3))