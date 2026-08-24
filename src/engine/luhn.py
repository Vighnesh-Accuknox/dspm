def luhn_check(card_number: str) -> bool:
    """
    Validates a credit card number using the Luhn algorithm.
    """
    # Keep only digits
    digits = [int(char) for char in card_number if char.isdigit()]
    if not digits or len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            if doubled > 9:
                doubled -= 9
            checksum += doubled
        else:
            checksum += digit

    return checksum % 10 == 0
