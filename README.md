# Detecting Nmap Scans with Zeek

Network Security – Assignment 10.2 (Aalborg University)

Zeek scripts that detect Nmap scanning activity in the CIC-IDS2017 pcap snippet.

## Scripts

| Script | Scan | Detection pattern (conn.log history) |
|---|---|---|
| `scripts/detect_sS.zeek` | SYN scan (`-sS`) | `ShR` – SYN, SYN-ACK, RST (half-open) |
| `scripts/detect_sT.zeek` | TCP Connect scan (`-sT`) | `ShAR` – SYN, SYN-ACK, ACK, RST (full handshake) |

Each script counts matching connections per source IP. When a host reaches the
threshold (default: 50), a Notice is raised, the counter restarts, and the
Notice message includes the number of previous Notices for the same scan.

## Usage

Tested with Zeek 9.0.0.

    zeek -C -r <pcap file> scripts/detect_sS.zeek
    zeek -C -r <pcap file> scripts/detect_sT.zeek

Results are written to `notice.log`:

    zeek-cut note msg < notice.log

Change the threshold without editing the script:

    zeek -C -r <pcap file> scripts/detect_sS.zeek SynScan::threshold=20