### Wireshark Lab: Network Protocol and Traffic Analysis

A hands-on network analysis lab investigating protocol behavior, cleartext data exposure, and transport-layer connection states using Wireshark.

The exercises were conducted on a Windows host using controlled network interactions to evaluate packet-level evidence. Scenarios covered foundational protocol flow (DNS, ARP, TCP handshake and teardown), security risks of unencrypted HTTP authentication, and TCP handshake behavior under open versus closed port conditions.

### Objectives
- Capture and analyze local network traffic using Wireshark display filters.
- Trace and document protocol sequences including DNS resolution and TCP session establishment/teardown.
- Evaluate the security implications of cleartext application protocols (HTTP) compared to encrypted transport (TLS).
- Observe and verify TCP connection states (SYN/ACK vs. RST/ACK) using targeted port probing.
- Document network findings with defensible technical accuracy, distinguishing verified packet data from unobserved metadata.

### Lab Environment
| Component | Configuration |
|---|---|
| Host Platform | Windows laptop |
| Capture Tool | Wireshark (Npcap packet capture driver) |
| Monitored Interface | Wi-Fi network interface |
| Probing Utility | PowerShell (`Test-NetConnection`) |
| Local Gateway Target | `192.168.1.1` (Default Gateway) |
| Web Test Target | `testfire.net` (Insecure demonstration web application) |

---

### Traffic Analysis Scenarios

#### 1. Baseline Protocol Flow: DNS & TCP Session Lifecycle
**Purpose:** Verify fundamental name resolution and transport-layer connection mechanics.

I captured DNS queries and responses along with standard web browsing traffic, isolating conversations using Wireshark display filters (`dns`, `tcp.port == 80`, `ip.addr`).

**Verified Observations:**
- **DNS Resolution:** Verified standard recursive query/response transactions over UDP port 53. Inspection of the DNS payload confirmed mapped `A` (IPv4) and `AAAA` (IPv6) records corresponding to requested domains.
- **TCP Three-Way Handshake:** Observed sequence synchronization across client and server:
  1. Client sends `[SYN]` (Initial Sequence Number synchronized).
  2. Server responds with `[SYN, ACK]`.
  3. Client acknowledges with `[ACK]`, transitioning the state to `ESTABLISHED`.
- **Session Termination:** Traced graceful connection teardown using the bidirectional `[FIN, ACK]` handshake, concluding with final acknowledgments.

**Interpretation:** Baseline packet analysis confirms proper protocol compliance and establishes normal operational benchmarks required before identifying anomalies or malicious traffic.

---

#### 2. Cleartext Transmission vs. Transport Encryption
**Purpose:** Evaluate exposure of sensitive user input in unencrypted HTTP traffic versus TLS session security.

I submitted test credentials containing dummy authentication data to a public demonstration banking application (`testfire.net`) over standard HTTP, and compared the capture against subsequent encrypted HTTPS traffic.

**Verified Observations:**
- **HTTP POST Analysis:** Using Wireshark's *Follow TCP Stream* feature, the unencrypted HTTP transaction revealed the complete request payload in plain text, including:
  - Request method and target URI (`POST /login.jsp`).
  - Standard HTTP headers (Host, User-Agent, Content-Type).
  - Explicit credential parameters (`uid` and `pass`) submitted directly via form-encoded data.
- **TLS Comparison:** Under HTTPS/TLS 1.2+, the same interaction encapsulated application data into opaque TLS records (`Application Data`). Payload contents, parameters, and application URIs were fully concealed from passive packet inspection.

**Interpretation:** Cleartext HTTP exposes sensitive application data to trivial interception on the local network segment. Transport Layer Security (TLS) prevents payload exposure, restricting passive network observation to packet headers, IP endpoints, and negotiated TLS parameters.

---

#### 3. Transport-Layer Probing: Open vs. Closed Port States
**Purpose:** Observe packet-level responses during controlled TCP connection attempts to open and closed service ports.

Using PowerShell's `Test-NetConnection` cmdlet, I initiated controlled single-port probes from the Windows host to the local gateway router (`192.168.1.1`) across three specific ports:
- Port `80` (HTTP web management)
- Port `81` (Arbitrary unassigned port)
- Port `82` (Arbitrary unassigned port)

**Verified Observations:**
- **Port 80 (Open Service):** The gateway completed the full TCP three-way handshake (`SYN` -> `SYN, ACK` -> `ACK`), confirming an active HTTP service listening on the gateway management interface.
- **Ports 81 and 82 (Closed Services):** In response to the client's initial `[SYN]` packet, the gateway immediately returned a packet with the reset and acknowledgment flags set (`[RST, ACK]`).

**Interpretation:** 
- A listening TCP service accepts connection requests by returning `SYN, ACK`.
- An active host with no service bound to a queried port indicates rejection by terminating the attempt with `RST, ACK`.
- This controlled exercise demonstrated exact transport-layer signaling under individual port queries, rather than a broad automated port scan.

---

### Results Summary
| Scenario | Target | Protocol / Flags | Recorded Packet Evidence |
|---|---|---|---|
| DNS & Handshake | Internet endpoints | DNS / TCP (`SYN`, `FIN`) | Mapped A-records; completed 3-way handshake and 4-step teardown |
| Cleartext Authentication | `testfire.net` | HTTP (`POST`) | Plaintext form fields (`uid`, `pass`) readable via TCP stream following |
| Encrypted Session | Secure web targets | TLS 1.2+ | Encrypted Application Data payload; content hidden from inspection |
| Gateway Probe: Port 80 | `192.168.1.1` | TCP (`SYN` / `SYN, ACK`) | Full handshake completed; service listening |
| Gateway Probe: Ports 81/82 | `192.168.1.1` | TCP (`SYN` / `RST, ACK`) | Immediate connection reset (`RST, ACK`); service closed |

---

### Key Takeaways
- **Packet-Level Grounding:** Protocol analysis in Wireshark provides ground-truth visibility into network communications, bypassing higher-level application abstractions.
- **Risks of Unencrypted Protocols:** Credentials and operational data transmitted across cleartext channels (HTTP) are fully exposed to passive eavesdropping.
- **Transport Diagnostics:** Observing TCP flag combinations (`SYN/ACK` vs. `RST/ACK`) provides precise diagnosis of service availability and network behavior without relying on proprietary scanner outputs.
- **Technical Precision in Reporting:** Clear distinction must be maintained between verified payload evidence (such as extracted HTTP fields) and encrypted traffic where only transport and network metadata remain accessible.

---

### Scope and Limitations
- The lab was conducted in a controlled home network environment using self-generated traffic and authorized demonstration endpoints (`testfire.net`).
- Testing focused on standard protocol evaluation and localized port probing; it did not encompass full automated vulnerability scanning, IDS/IPS evasion, or packet injection.
- Plaintext credential inspection was performed strictly using dummy values.

---

### Potential Follow-up Work
- Capture and analyze an active network scan (e.g., Nmap SYN stealth scan) to contrast automated scanning patterns against single manual probes.
- Inspect TLS 1.3 handshakes to evaluate privacy improvements over older TLS versions (e.g., Encrypted Extensions).
- Export and parse PCAP files using command-line utilities such as `tshark` for automated analysis workflows.
