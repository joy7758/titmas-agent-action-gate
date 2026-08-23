import re
import timeit

source_commit = "1234567890abcdef1234567890abcdef12345678"
invalid_commit = "1234567890abcdef1234567890abcdef1234567g"
hex_set = set("0123456789abcdef")
hex_pattern = re.compile(r"^[0-9a-f]{40}$")


def original(val):
    return not isinstance(val, str) or len(val) != 40 or any(v not in "0123456789abcdef" for v in val)


def with_set(val):
    return not isinstance(val, str) or len(val) != 40 or not set(val).issubset(hex_set)


def with_regex(val):
    return not isinstance(val, str) or not hex_pattern.match(val)


def with_int(val):
    if not isinstance(val, str) or len(val) != 40:
        return True
    try:
        # this accepts uppercase and signs, so maybe not exact match
        int(val, 16)
        return not val.islower() and not val.isdigit()  # this is complicated
    except ValueError:
        return True


print("Original (valid):", timeit.timeit("original(source_commit)", globals=globals(), number=100000))
print("Original (invalid):", timeit.timeit("original(invalid_commit)", globals=globals(), number=100000))

print("Set (valid):", timeit.timeit("with_set(source_commit)", globals=globals(), number=100000))
print("Set (invalid):", timeit.timeit("with_set(invalid_commit)", globals=globals(), number=100000))

print("Regex (valid):", timeit.timeit("with_regex(source_commit)", globals=globals(), number=100000))
print("Regex (invalid):", timeit.timeit("with_regex(invalid_commit)", globals=globals(), number=100000))
