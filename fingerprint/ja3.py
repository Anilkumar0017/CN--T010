import hashlib


def is_grease(value):
    """
    Check whether a TLS value is a GREASE value.
    """

    return (value & 0x0F0F) == 0x0A0A


def remove_grease(values):
    """
    Remove GREASE values from a list.
    """

    return [
        value for value in values
        if not is_grease(value)
    ]


def calculate_ja3(
    version,
    cipher_suites,
    extensions,
    supported_groups,
    ec_point_formats
):
    """
    Calculate JA3 fingerprint.

    JA3 format:

    TLSVersion,
    CipherSuites,
    Extensions,
    EllipticCurves,
    ECPointFormats
    """

    # Remove GREASE values
    cipher_suites = remove_grease(cipher_suites)
    extensions = remove_grease(extensions)
    supported_groups = remove_grease(supported_groups)

    # Convert lists to JA3 format
    cipher_string = "-".join(
        str(x) for x in cipher_suites
    )

    extension_string = "-".join(
        str(x) for x in extensions
    )

    group_string = "-".join(
        str(x) for x in supported_groups
    )

    point_format_string = "-".join(
        str(x) for x in ec_point_formats
    )

    # Build JA3 string
    ja3_string = (
        f"{version},"
        f"{cipher_string},"
        f"{extension_string},"
        f"{group_string},"
        f"{point_format_string}"
    )

    # Calculate MD5
    ja3_hash = hashlib.md5(
        ja3_string.encode()
    ).hexdigest()

    return ja3_string, ja3_hash