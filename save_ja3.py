import csv
import os
from datetime import datetime

from fingerprint_database import FINGERPRINTS


FILE_NAME = "ja3_database.csv"

HEADER = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "tls_version",
    "ja3_string",
    "ja3_hash",
    "application",
    "version",
    "tls_stack"
]


def migrate_old_csv():
    """
    Convert an old 9-column CSV into the new 11-column format.
    Existing fingerprints are also identified using the database.
    """

    if not os.path.exists(FILE_NAME):
        return

    with open(
        FILE_NAME,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        rows = list(csv.reader(file))

    if not rows:
        return

    old_header = rows[0]

    # Already using the new format
    if old_header == HEADER:
        return

    new_rows = []

    for row in rows[1:]:

        if len(row) < 8:
            continue

        # First 8 columns are common to both formats
        new_row = row[:8]

        ja3_hash = row[7]

        # Existing application information
        if len(row) >= 9:
            application = row[8]
        else:
            application = "Unknown"

        if len(row) >= 10:
            version = row[9]
        else:
            version = "Unknown"

        if len(row) >= 11:
            tls_stack = row[10]
        else:
            tls_stack = "Unknown"

        # Identify using fingerprint database
        fingerprint = FINGERPRINTS.get(ja3_hash)

        if fingerprint:

            application = fingerprint.get(
                "application",
                application
            )

            version = fingerprint.get(
                "version",
                version
            )

            tls_stack = fingerprint.get(
                "tls_stack",
                tls_stack
            )

        new_row.extend([
            application,
            version,
            tls_stack
        ])

        new_rows.append(new_row)

    # Rewrite CSV using new format
    with open(
        FILE_NAME,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(HEADER)

        writer.writerows(new_rows)


def save_ja3(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    tls_version,
    ja3_string,
    ja3_hash,
    application,
    client_version,
    tls_stack
):

    # Upgrade old CSV if necessary
    migrate_old_csv()

    file_exists = os.path.exists(FILE_NAME)

    with open(
        FILE_NAME,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        if not file_exists:

            writer.writerow(HEADER)

        writer.writerow([
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            tls_version,
            ja3_string,
            ja3_hash,
            application,
            client_version,
            tls_stack
        ])


print("JA3 CSV logger is ready.")