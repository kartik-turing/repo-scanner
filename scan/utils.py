import math
import re


def calculate_entropy(string):
    if not string:
        return 0
    entropy = 0
    for char in set(string):
        p = string.count(char) / len(string)
        entropy -= p * math.log2(p)
    return entropy


def detect_high_entropy_strings(content, threshold=4.5):
    strings = re.findall(r'[\'"]([^\'"]{10,})[\'"]', content)
    high_entropy = []
    for s in strings:
        entropy = calculate_entropy(s)
        if entropy > threshold:
            high_entropy.append(s)
    return high_entropy
