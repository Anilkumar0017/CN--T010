\# TLS Fingerprinting and Traffic Analysis



\## 1. Project Overview



This project implements a passive TLS fingerprinting system for analyzing encrypted network traffic.



The system captures HTTPS traffic, extracts TLS ClientHello and ServerHello information, calculates JA3 and JA3S fingerprints, compares the fingerprints with a local fingerprint database, identifies known and unknown TLS clients, stores the results in CSV format, correlates client and server fingerprints, and generates a statistical dashboard.



The project was implemented using Python and Scapy on Windows.



\---



\## 2. Objectives



The main objectives of the project are:



\- Capture TLS network traffic.

\- Analyze TLS ClientHello messages.

\- Extract TLS parameters required for JA3 fingerprinting.

\- Calculate JA3 fingerprints.

\- Remove GREASE values before fingerprint calculation.

\- Maintain a fingerprint database.

\- Identify known and unknown TLS clients.

\- Extract TLS ServerHello information.

\- Calculate JA3S fingerprints.

\- Correlate JA3 and JA3S fingerprints within the same TCP connection.

\- Store fingerprint observations in CSV format.

\- Generate statistical reports.

\- Visualize TLS traffic using charts.



\---



\## 3. Technologies Used



\### Programming Language



Python 3



\### Libraries



\- Scapy

\- pandas

\- matplotlib

\- cryptography



\### Operating System



Windows



\### Network Capture



\- Scapy

\- Npcap



\### Data Storage



CSV



\---



\## 4. System Architecture



The system follows the following processing pipeline:



Network Traffic



↓



Packet Capture



↓



PCAP File



↓



TCP Stream Reconstruction



↓



TLS ClientHello / ServerHello Extraction



↓



JA3 / JA3S Calculation



↓



Fingerprint Database



↓



Known / Unknown Classification



↓



CSV Storage



↓



Flow Correlation



↓



Report and Dashboard



\---



\## 5. JA3 Fingerprinting



JA3 is calculated from information contained in the TLS ClientHello message.



The JA3 structure used in this project is:



TLS Version,

Cipher Suites,

Extensions,

Supported Groups,

EC Point Formats



The resulting JA3 string is hashed using MD5 to produce the JA3 fingerprint.



GREASE values are removed before calculating the fingerprint.



\---



\## 6. JA3S Fingerprinting



JA3S is calculated from the TLS ServerHello message.



The JA3S structure used in this project is:



TLS Version,

Selected Cipher,

Extensions



The resulting JA3S string is hashed using MD5.



\---



\## 7. Fingerprint Database



The project contains fingerprints observed during controlled experiments.



The database contains fingerprints associated with:



\- curl

\- Python SSL

\- Chrome

\- Firefox

\- Microsoft Edge



The database contains six JA3 entries because different Python/OpenSSL environments can produce different fingerprints.



Fingerprint labels in this project represent observations from controlled experiments and are not treated as universal application identifiers.



\---



\## 8. Project Files



\### Packet Capture



`capture.py`



Basic packet capture implementation.



`capture\_pcap.py`



Captures TCP port 443 traffic and saves it as a PCAP file.



\---



\### Packet Analysis



`inspect\_pcap.py`



Inspects captured packets and identifies TLS records.



`pcap\_ja3.py`



Performs TCP stream reconstruction, ClientHello extraction, JA3 calculation, fingerprint lookup, and CSV logging.



\---



\### JA3



`fingerprint/ja3.py`



Contains the JA3 calculation and GREASE filtering functions.



`fingerprint\_database.py`



Contains the known JA3 fingerprint database.



`test\_ja3.py`



Tests the JA3 calculation.



\---



\### JA3S



`ja3s.py`



Extracts TLS ServerHello messages and calculates JA3S fingerprints.



`ja3s\_database.py`



Contains the known JA3S fingerprint database.



\---



\### Correlation



`correlate.py`



Associates JA3 and JA3S fingerprints belonging to the same TCP connection.



\---



\### Reporting



`save\_ja3.py`



Stores fingerprint observations in CSV format.



`report.py`



Generates a textual fingerprint report.



`final\_analysis.py`



Generates the final project statistics and known/unknown fingerprint summary.



`dashboard.py`



Generates graphical visualizations of TLS traffic.



\---



\## 9. Experimental Results



The final experimental dataset contained:



\- Total TLS connections: 51

\- Unique JA3 fingerprints: 15

\- Known connections: 26

\- Unknown connections: 25



Client application observations were:



| Application | Connections |

|------------|-------------|

| Unknown | 25 |

| Python SSL | 13 |

| Chrome | 5 |

| Microsoft Edge | 4 |

| curl | 2 |

| Firefox | 2 |



The results demonstrate that the system can distinguish fingerprints observed in controlled experiments while also detecting previously unknown fingerprints.



\---



\## 10. JA3S Results



The system successfully extracted ServerHello information and generated JA3S fingerprints.



One controlled JA3S observation was:



JA3S:



771,4866,43-51



JA3S Hash:



15af977ce25de452b96affa2addb1036



\---



\## 11. Flow Correlation



The system successfully correlated client-side JA3 and server-side JA3S fingerprints.



In the final PCAP analysis:



\- TCP connections correlated: 8



The correlation process allows the system to associate a TLS client fingerprint with the corresponding server fingerprint within the same network flow.



\---



\## 12. Dashboard



The project generates three visualizations:



1\. TLS connections by client application.

2\. Unique JA3 fingerprints by application.

3\. TLS traffic distribution by application.



The generated charts are stored in the `results` directory.



\---



\## 13. Limitations



The project has several limitations:



\- JA3 fingerprints are not guaranteed to uniquely identify an application.

\- Fingerprints may change between software versions and configurations.

\- Unknown fingerprints require additional investigation.

\- The system analyzes metadata from TLS handshakes and does not decrypt TLS application data.

\- The fingerprint database is based on controlled observations.



\---



\## 14. Future Work



Possible future improvements include:



\- JA4 and JA4+ fingerprinting.

\- Larger fingerprint databases.

\- Real-time TLS fingerprint monitoring.

\- Machine-learning based fingerprint classification.

\- Centralized fingerprint storage.

\- High-performance packet processing using eBPF/XDP.

\- Integration with security monitoring systems.



\---



\## 15. Conclusion



This project demonstrates a complete passive TLS fingerprinting workflow.



The implemented system captures HTTPS traffic, reconstructs TCP streams, extracts TLS handshake information, calculates JA3 and JA3S fingerprints, identifies known and unknown fingerprints, correlates client and server fingerprints, stores observations, and generates reports and visualizations.



The final experiment analyzed 51 TLS connections and identified 15 unique JA3 fingerprints.



The project successfully demonstrates how TLS handshake metadata can be used for network traffic analysis without inspecting encrypted application content.

