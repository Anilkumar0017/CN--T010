import csv
from collections import Counter

from fingerprint_database import FINGERPRINTS


CSV_FILE = "ja3_database.csv"


print("==============================================")
print("        TLS FINGERPRINTING FINAL REPORT")
print("==============================================")
print()


# ============================================================
# LOAD CSV
# ============================================================

try:

    with open(
        CSV_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        rows = list(reader)

except FileNotFoundError:

    print("ERROR: ja3_database.csv was not found.")
    exit()


if not rows:

    print("No TLS fingerprint records found.")
    exit()


# ============================================================
# BASIC STATISTICS
# ============================================================

total_connections = len(rows)

ja3_hashes = set(
    row["ja3_hash"]
    for row in rows
    if row.get("ja3_hash")
)


# ============================================================
# APPLICATION SUMMARY
# USE CURRENT FINGERPRINT DATABASE
# ============================================================

applications = Counter()


for row in rows:

    ja3_hash = row.get(
        "ja3_hash",
        ""
    )

    fingerprint = FINGERPRINTS.get(
        ja3_hash
    )

    if fingerprint:

        application = fingerprint.get(
            "application",
            "Unknown"
        )

    else:

        application = "Unknown"

    applications[application] += 1


# ============================================================
# KNOWN / UNKNOWN CONNECTIONS
# USE CURRENT FINGERPRINT DATABASE
# ============================================================

known_connections = 0
unknown_connections = 0


for row in rows:

    ja3_hash = row.get(
        "ja3_hash",
        ""
    )

    if ja3_hash in FINGERPRINTS:

        known_connections += 1

    else:

        unknown_connections += 1


# ============================================================
# DISPLAY PROJECT OVERVIEW
# ============================================================

print("PROJECT OVERVIEW")
print("----------------------------------------------")

print(
    "Total TLS Connections :",
    total_connections
)

print(
    "Unique JA3 Hashes     :",
    len(ja3_hashes)
)

print(
    "Known Connections     :",
    known_connections
)

print(
    "Unknown Connections   :",
    unknown_connections
)

print()


# ============================================================
# APPLICATION SUMMARY
# ============================================================

print("CLIENT APPLICATION SUMMARY")
print("----------------------------------------------")


for application, count in applications.most_common():

    print(
        f"{application:<25}: {count}"
    )


print()


# ============================================================
# KNOWN FINGERPRINTS
# ============================================================

print("KNOWN FINGERPRINTS")
print("----------------------------------------------")


known_hashes = {}


for row in rows:

    ja3_hash = row.get(
        "ja3_hash",
        ""
    )

    fingerprint = FINGERPRINTS.get(
        ja3_hash
    )

    if not fingerprint:

        continue


    if ja3_hash not in known_hashes:

        known_hashes[ja3_hash] = {

            "application": fingerprint.get(
                "application",
                "Unknown"
            ),

            "version": fingerprint.get(
                "version",
                "Unknown"
            ),

            "tls_stack": fingerprint.get(
                "tls_stack",
                "Unknown"
            )
        }


for ja3_hash, info in known_hashes.items():

    print()

    print(
        "Application :",
        info["application"]
    )

    print(
        "Version     :",
        info["version"]
    )

    print(
        "TLS Stack   :",
        info["tls_stack"]
    )

    print(
        "JA3         :",
        ja3_hash
    )


print()


# ============================================================
# UNKNOWN FINGERPRINTS
# ============================================================

unknown_hashes = Counter()


for row in rows:

    ja3_hash = row.get(
        "ja3_hash",
        ""
    )

    if ja3_hash and ja3_hash not in FINGERPRINTS:

        unknown_hashes[ja3_hash] += 1


print("UNKNOWN FINGERPRINTS")
print("----------------------------------------------")


if not unknown_hashes:

    print("None")

else:

    for ja3_hash, count in unknown_hashes.most_common():

        print()

        print(
            "JA3         :",
            ja3_hash
        )

        print(
            "Occurrences :",
            count
        )


# ============================================================
# FINAL STATUS
# ============================================================

print()
print("==============================================")
print("              FINAL STATUS")
print("==============================================")

print()


if known_connections > 0:

    print(
        "Fingerprint identification : WORKING"
    )

else:

    print(
        "Fingerprint identification : NOT VERIFIED"
    )


if unknown_connections > 0:

    print(
        "Unknown fingerprint detection : WORKING"
    )

else:

    print(
        "Unknown fingerprint detection : NONE"
    )


print()

print(
    "TLS fingerprinting analysis completed."
)

print("==============================================")