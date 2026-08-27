import math


def calculate_entropy(candidate: str) -> float:
    """
    Calculates the Shannon entropy of a given string.
    """
    if not candidate:
        return 0.0

    frequencies = {}
    for char in candidate:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    total_chars = len(candidate)
    for count in frequencies.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)

    return entropy
