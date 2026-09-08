import csv
from collections import Counter

from fingerprint_database import FINGERPRINTS


CSV_FILE = "ja3_database.csv"


print("==============================================")
print("          TLS FINGERPRINTING REPORT")
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
# TOTAL CONNECTIONS
# ============================================================

total_connections = len(rows)


# ============================================================
# UNIQUE JA3 FINGERPRINTS
# ============================================================

ja3_hashes = set()

for row in rows:

    ja3_hash = row.get(
        "ja3_hash",
        ""
    )

    if ja3_hash:

        ja3_hashes.add(
            ja3_hash
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
# HEADER
# ============================================================

print(
    "Total TLS Connections :",
    total_connections
)

print(
    "Unique JA3 Fingerprints:",
    len(ja3_hashes)
)

print()


# ============================================================
# CLIENT APPLICATIONS
# ============================================================

print("==============================================")
print("             CLIENT APPLICATIONS")
print("==============================================")
print()


for application, count in applications.most_common():

    print(
        f"{application:<25}: {count}"
    )


# ============================================================
# JA3 FINGERPRINTS
# ============================================================

print()
print("==============================================")
print("             JA3 FINGERPRINTS")
print("==============================================")


# ------------------------------------------------------------
# Get unique fingerprints
# ------------------------------------------------------------

fingerprints_found = {}


for row in rows:

    ja3_hash = row.get(
        "ja3_hash",
        ""
    )

    if not ja3_hash:

        continue


    # Check current database

    fingerprint = FINGERPRINTS.get(
        ja3_hash
    )


    if fingerprint:

        application = fingerprint.get(
            "application",
            "Unknown"
        )

        version = fingerprint.get(
            "version",
            "Unknown"
        )

        tls_stack = fingerprint.get(
            "tls_stack",
            "Unknown"
        )

    else:

        application = "Unknown"

        version = "Unknown"

        tls_stack = "Unknown"


    fingerprints_found[ja3_hash] = {

        "application": application,

        "version": version,

        "tls_stack": tls_stack
    }


# ------------------------------------------------------------
# Display fingerprints
# ------------------------------------------------------------

for ja3_hash, info in fingerprints_found.items():

    print()
    print("----------------------------------------------")

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


# ============================================================
# SUMMARY
# ============================================================

print()
print("==============================================")
print("       UNIQUE FINGERPRINT SUMMARY")
print("==============================================")
print()

print(
    "Number of unique JA3 fingerprints:",
    len(fingerprints_found)
)

print()
print("Report generation completed.")
print("==============================================")