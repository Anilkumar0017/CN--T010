from fingerprint.ja3 import calculate_ja3


version = 771

ciphers = [
    4866,
    4865,
    49196,
    49195,
    49200,
    49199,
    49188,
    49187,
    49192,
    49191,
    49162,
    49161,
    49172,
    49171,
    157,
    156,
    61,
    60,
    53,
    47
]

extensions = [
    0,
    5,
    43,
    13,
    35,
    10,
    11,
    16,
    51,
    45,
    23,
    65281,
    41
]

supported_groups = [
    29,
    23,
    24
]

ec_point_formats = [
    0
]


ja3_string, ja3_hash = calculate_ja3(
    version,
    ciphers,
    extensions,
    supported_groups,
    ec_point_formats
)


print("====================================")
print("             JA3 RESULT")
print("====================================")

print()
print("JA3 String:")
print(ja3_string)

print()
print("JA3 Hash:")
print(ja3_hash)

print()
print("====================================")