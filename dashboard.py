import pandas as pd
import matplotlib.pyplot as plt
import os

from fingerprint_database import FINGERPRINTS


FILE_NAME = "ja3_database.csv"


print("==============================================")
print("          TLS FINGERPRINT DASHBOARD")
print("==============================================")
print()


# ----------------------------------------------
# CHECK CSV FILE
# ----------------------------------------------

if not os.path.exists(FILE_NAME):

    print("ERROR: ja3_database.csv was not found.")
    exit()


# ----------------------------------------------
# LOAD CSV
# ----------------------------------------------

data = pd.read_csv(FILE_NAME)


# ----------------------------------------------
# CHECK COLUMNS
# ----------------------------------------------

if "ja3_hash" not in data.columns:

    print("ERROR: ja3_hash column not found.")
    exit()


# ----------------------------------------------
# IDENTIFY APPLICATIONS USING DATABASE
# ----------------------------------------------

def identify_application(ja3_hash):

    fingerprint = FINGERPRINTS.get(
        ja3_hash
    )

    if fingerprint:

        return fingerprint.get(
            "application",
            "Unknown"
        )

    return "Unknown"


data["identified_application"] = (
    data["ja3_hash"]
    .fillna("")
    .apply(identify_application)
)


# ----------------------------------------------
# BASIC STATISTICS
# ----------------------------------------------

total_connections = len(data)

unique_fingerprints = (
    data["ja3_hash"]
    .nunique()
)


application_counts = (
    data["identified_application"]
    .value_counts()
)


print(
    "Total TLS Connections :",
    total_connections
)

print(
    "Unique JA3 Fingerprints:",
    unique_fingerprints
)

print()


# ----------------------------------------------
# APPLICATION SUMMARY
# ----------------------------------------------

print("Client Application Summary")
print("----------------------------------------------")


for application, count in application_counts.items():

    print(
        f"{application:<25} : {count}"
    )


print()


# ==============================================
# CHART 1
# ==============================================

print("Creating Chart 1...")


plt.figure(
    figsize=(10, 6)
)


application_counts.plot(
    kind="bar"
)


plt.title(
    "TLS Connections by Client Application"
)

plt.xlabel(
    "Client Application"
)

plt.ylabel(
    "Number of Connections"
)

plt.xticks(
    rotation=30,
    ha="right"
)

plt.tight_layout()


plt.savefig(
    "tls_connections_by_application.png",
    dpi=300
)

plt.close()


print(
    "Chart 1 saved successfully."
)


# ==============================================
# CHART 2
# ==============================================

print("Creating Chart 2...")


fingerprint_counts = (
    data[
        data["identified_application"] != "Unknown"
    ]
    .groupby(
        "identified_application"
    )["ja3_hash"]
    .nunique()
    .sort_values(
        ascending=False
    )
)


# Add Unknown fingerprints separately

unknown_fingerprint_count = (
    data[
        data["identified_application"] == "Unknown"
    ]["ja3_hash"]
    .nunique()
)


if unknown_fingerprint_count > 0:

    fingerprint_counts.loc[
        "Unknown"
    ] = unknown_fingerprint_count


fingerprint_counts = (
    fingerprint_counts
    .sort_values(
        ascending=False
    )
)


plt.figure(
    figsize=(10, 6)
)


fingerprint_counts.plot(
    kind="bar"
)


plt.title(
    "Unique JA3 Fingerprints by Application"
)

plt.xlabel(
    "Client Application"
)

plt.ylabel(
    "Unique JA3 Fingerprints"
)

plt.xticks(
    rotation=30,
    ha="right"
)

plt.tight_layout()


plt.savefig(
    "unique_ja3_by_application.png",
    dpi=300
)

plt.close()


print(
    "Chart 2 saved successfully."
)


# ==============================================
# CHART 3
# ==============================================

print("Creating Chart 3...")


plt.figure(
    figsize=(8, 8)
)


application_counts.plot(
    kind="pie",
    autopct="%1.1f%%"
)


plt.title(
    "TLS Traffic Distribution by Application"
)

plt.ylabel("")


plt.tight_layout()


plt.savefig(
    "tls_application_distribution.png",
    dpi=300
)

plt.close()


print(
    "Chart 3 saved successfully."
)


# ==============================================
# FINAL RESULT
# ==============================================

print()

print("==============================================")
print("       DASHBOARD GENERATION COMPLETED")
print("==============================================")

print()


print(
    "Total connections :",
    total_connections
)

print(
    "Unique JA3 hashes :",
    unique_fingerprints
)

print(
    "Applications found:",
    len(application_counts)
)

print()


print("Generated files:")
print("----------------------------------------------")


print(
    "tls_connections_by_application.png"
)

print(
    "unique_ja3_by_application.png"
)

print(
    "tls_application_distribution.png"
)


print()

print(
    "Dashboard completed successfully."
)

print("==============================================")