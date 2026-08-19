from __future__ import annotations

import re
from pathlib import Path
import json

from .runtime_paths import resolve_data_file
from .rulesets import build_packet_text, normalize_action, normalize_match, rule_matches_packet
from .utils import normalize_protocol_name, safe_int


DEFAULT_MONITORS = [
    {
        "id": "builtin-credentials",
        "name": "Cleartext credentials",
        "description": "Username/password fields sent in the clear (HTTP forms, plaintext protocols).",
        "enabled": True,
        "priority": 10,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"pass(word|wd)?\s*[:=]",
                r"user(name)?\s*[:=]",
                r"\blogin\s*[:=]",
            ]
        },
        "action": {"tag": "credentials", "label": "Cleartext credentials", "severity": "high"},
    },
    {
        "id": "builtin-admin-ports",
        "name": "Sensitive admin ports",
        "description": "Traffic on commonly abused administrative/remote-access ports.",
        "enabled": True,
        "priority": 20,
        "source": "builtin",
        "mode": "rule",
        "match": {"ports": [21, 23, 135, 139, 445, 3389, 5900]},
        "action": {"tag": "admin-port", "label": "Admin port", "severity": "medium"},
    },
    {
        "id": "builtin-sqli",
        "name": "SQL injection pattern",
        "description": "Common SQL injection payload signatures.",
        "enabled": True,
        "priority": 30,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"union\s+select",
                r"or\s+1\s*=\s*1",
                r"drop\s+table",
                r"'\s*or\s*'1'\s*=\s*'1",
            ]
        },
        "action": {"tag": "sqli", "label": "SQL injection", "severity": "high"},
    },
    {
        "id": "builtin-xss",
        "name": "XSS pattern",
        "description": "Common cross-site scripting payload signatures.",
        "enabled": True,
        "priority": 40,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"<script",
                r"onerror\s*=",
                r"javascript:",
            ]
        },
        "action": {"tag": "xss", "label": "XSS attempt", "severity": "medium"},
    },
    {
        "id": "builtin-icmp-oversized",
        "name": "Oversized ICMP",
        "description": "Unusually large ICMP/ICMPv6 payloads, a common tunneling/exfiltration signal.",
        "enabled": True,
        "priority": 50,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["icmp", "icmpv6"], "min_length": 128},
        "action": {"tag": "icmp-oversized", "label": "Oversized ICMP", "severity": "medium"},
    },
    {
        "id": "builtin-l2-discovery",
        "name": "L2/discovery traffic",
        "description": "ARP resolution chatter, kept by default so host discovery (Radar/Map) stays populated.",
        "enabled": True,
        "priority": 60,
        "source": "builtin",
        "mode": "rule",
        "match": {"eth_types": [0x0806]},
        "action": {"tag": "discovery", "label": "L2 discovery", "severity": "info"},
    },
    {
        "id": "builtin-dns-domains",
        "name": "DNS domain lookups",
        "description": "DNS traffic on port 53. Feeds the Domains catalog with queried domain names.",
        "enabled": True,
        "priority": 70,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["udp", "tcp"], "ports": [53]},
        "action": {"tag": "dns", "label": "DNS lookup", "severity": "info"},
    },
    {
        "id": "builtin-http-requests",
        "name": "HTTP requests",
        "description": "Plaintext HTTP requests. Feeds the Paths catalog with request methods/paths and the Domains catalog with Host headers.",
        "enabled": True,
        "priority": 80,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "protocols": ["tcp"],
            "payload_contains": ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/1."],
        },
        "action": {"tag": "http-request", "label": "HTTP request", "severity": "info"},
    },
    {
        "id": "builtin-tls-sni",
        "name": "TLS SNI / HTTPS domains",
        "description": "TLS ClientHello handshakes. Feeds the Domains catalog with the requested server name (SNI).",
        "enabled": True,
        "priority": 90,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [443, 8443, 9443], "payload_prefix_hex": ["16"]},
        "action": {"tag": "tls-sni", "label": "TLS SNI", "severity": "info"},
    },
    {
        "id": "builtin-insecure-telnet",
        "name": "Telnet traffic",
        "description": "Unencrypted remote-shell protocol. Credentials and session data travel in the clear.",
        "enabled": True,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [23]},
        "action": {"tag": "telnet", "label": "Telnet", "severity": "medium"},
    },
    {
        "id": "builtin-insecure-ftp",
        "name": "FTP traffic",
        "description": "Unencrypted file-transfer protocol. Credentials and commands travel in the clear.",
        "enabled": True,
        "priority": 110,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [21]},
        "action": {"tag": "ftp", "label": "FTP", "severity": "medium"},
    },
    {
        "id": "builtin-insecure-snmp",
        "name": "SNMP traffic",
        "description": "SNMP agent/manager traffic. Community strings (often 'public'/'private') travel unauthenticated in v1/v2c.",
        "enabled": True,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["udp"], "ports": [161, 162]},
        "action": {"tag": "snmp", "label": "SNMP", "severity": "medium"},
    },
    {
        "id": "builtin-http-basic-auth",
        "name": "HTTP Basic Auth",
        "description": "HTTP requests carrying a base64-encoded Basic Authorization header (credentials recoverable, not encrypted).",
        "enabled": True,
        "priority": 130,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"authorization:\s*basic\s+[a-z0-9+/=]+"]},
        "action": {"tag": "http-basic-auth", "label": "HTTP Basic Auth", "severity": "high"},
    },
    {
        "id": "builtin-dns-long-subdomain",
        "name": "DNS long/suspicious subdomain",
        "description": "DNS query names with an unusually long label, a common signature of DNS tunneling or data exfiltration.",
        "enabled": True,
        "priority": 140,
        "source": "builtin",
        "mode": "regex",
        "match": {"protocols": ["udp", "tcp"], "ports": [53], "payload_regex": [r"\b[a-z0-9][a-z0-9-]{39,}\.[a-z0-9.-]+\b"]},
        "action": {"tag": "dns-long-subdomain", "label": "Suspicious DNS subdomain", "severity": "medium"},
    },
    {
        "id": "builtin-dns-hex-subdomain",
        "name": "DNS hex-encoded subdomain",
        "description": "Long hex-only DNS query label, a common signature of DNS tunneling/C2 beaconing implants that hex-encode exfiltrated data or commands.",
        "enabled": True,
        "priority": 141,
        "source": "builtin",
        "mode": "regex",
        "match": {"protocols": ["udp", "tcp"], "ports": [53], "payload_regex": [r"\b[a-f0-9]{32,}\.[a-z0-9.-]+\b"]},
        "action": {"tag": "dns-hex-subdomain", "label": "Hex-encoded DNS subdomain", "severity": "medium"},
    },
    {
        "id": "builtin-dns-query-flood",
        "name": "DNS query flood",
        "description": "Stateful: flags a source sending an unusually high rate of DNS queries within a short window — bulk lookups are a common DGA-malware-beaconing or misbehaving-host signature.",
        "enabled": True,
        "priority": 145,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["udp", "tcp"], "ports": [53]},
        "action": {"tag": "dns-query-flood", "label": "DNS query flood", "severity": "medium"},
    },
    {
        "id": "builtin-arp-spoof",
        "name": "ARP spoofing / MITM",
        "description": "Stateful: flags an IP address whose ARP-announced MAC address changes, a classic ARP-spoofing/MITM signature.",
        "enabled": True,
        "priority": 15,
        "source": "builtin",
        "mode": "stateful",
        "match": {"eth_types": [0x0806]},
        "action": {"tag": "arp-spoof", "label": "ARP spoofing suspected", "severity": "critical"},
    },
    {
        "id": "builtin-icmp-flood",
        "name": "ICMP flood",
        "description": "Stateful: flags a source sending an unusually high rate of ICMP/ICMPv6 packets within a short window.",
        "enabled": True,
        "priority": 55,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["icmp", "icmpv6"]},
        "action": {"tag": "icmp-flood", "label": "ICMP flood", "severity": "high"},
    },
    {
        "id": "builtin-syn-flood",
        "name": "TCP SYN flood",
        "description": "Stateful: flags a source sending an unusually high rate of bare TCP SYN packets within a short window — the classic SYN-flood DoS signature.",
        "enabled": True,
        "priority": 6,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["tcp"]},
        "action": {"tag": "syn-flood", "label": "TCP SYN flood", "severity": "high"},
    },
    {
        "id": "builtin-brute-force-login",
        "name": "Login brute-force attempt",
        "description": "Stateful: flags repeated connection attempts from the same source to a credential-bearing service (SSH/RDP/FTP/Telnet/DB) within a short window.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["tcp"], "ports": [21, 22, 23, 25, 110, 143, 993, 995, 1433, 3306, 3389, 5432, 5900]},
        "action": {"tag": "brute-force-login", "label": "Login brute-force attempt", "severity": "high"},
    },
    {
        "id": "builtin-wifi-deauth-flood",
        "name": "WiFi deauth/disassoc flood",
        "description": "Stateful: flags a burst of 802.11 deauthentication/disassociation frames, a common WiFi DoS/handshake-capture attack. Only produces data while WiFi monitor mode is active.",
        "enabled": True,
        "priority": 150,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["wifi-mgmt"]},
        "action": {"tag": "wifi-deauth-flood", "label": "WiFi deauth flood", "severity": "high"},
    },
    {
        "id": "builtin-wifi-rogue-ap",
        "name": "WiFi rogue AP / evil twin",
        "description": "Stateful: flags an SSID broadcast from more than one BSSID, a common rogue-AP/evil-twin signature. Only produces data while WiFi monitor mode is active.",
        "enabled": True,
        "priority": 160,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["wifi-mgmt"]},
        "action": {"tag": "wifi-rogue-ap", "label": "WiFi rogue AP", "severity": "high"},
    },
    # The two detectors above only fire on an actual attack pattern (a burst,
    # or the same SSID from two BSSIDs) - on an ordinary capture window with
    # no attacker present they correctly produce nothing at all. The rule
    # monitors below give visibility into ordinary 802.11 management traffic
    # itself (what APs/clients are around, right now) so WiFi monitor mode
    # has something to show even without an active attack.
    {
        "id": "builtin-wifi-beacon-seen",
        "name": "WiFi beacon / AP seen",
        "description": "Access point beacon decoded (SSID, BSSID, channel, security) - every AP visible while WiFi monitor mode is active, not just attacks.",
        "enabled": True,
        "priority": 161,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["wifi-mgmt"], "payload_contains": ["802.11 beacon"]},
        "action": {"tag": "wifi-beacon", "label": "WiFi beacon", "severity": "info"},
    },
    {
        "id": "builtin-wifi-probe-request",
        "name": "WiFi probe request",
        "description": "A device is actively probing for a network (broadcast or by name) - normal WiFi scanning behavior, useful for spotting devices/SSIDs of interest nearby.",
        "enabled": True,
        "priority": 162,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["wifi-mgmt"], "payload_contains": ["802.11 probe-req"]},
        "action": {"tag": "wifi-probe-request", "label": "WiFi probe request", "severity": "info"},
    },
    {
        "id": "builtin-wifi-open-network",
        "name": "WiFi open/unencrypted network",
        "description": "A beacon advertises no WPA/WPA2/WPA3 protection - an open network, either intentional (guest WiFi) or a rogue/evil-twin AP impersonating a protected one.",
        "enabled": True,
        "priority": 163,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["wifi-mgmt"], "payload_contains": ["security=open"]},
        "action": {"tag": "wifi-open-network", "label": "WiFi open network", "severity": "medium"},
    },
    {
        "id": "builtin-wifi-deauth-event",
        "name": "WiFi deauth/disassoc event",
        "description": "A single 802.11 deauth/disassoc frame - fires on every occurrence, unlike builtin-wifi-deauth-flood which only fires on a burst. Deauth frames outside a known reconfiguration are a common attack signature even as single events.",
        "enabled": True,
        "priority": 164,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["wifi-mgmt"], "payload_contains": ["802.11 deauth", "802.11 disassoc"]},
        "action": {"tag": "wifi-deauth-event", "label": "WiFi deauth/disassoc", "severity": "high"},
    },
    {
        "id": "builtin-wifi-client-association",
        "name": "WiFi client association",
        "description": "A client is joining (or attempting to join) a network - association/reassociation request or response.",
        "enabled": True,
        "priority": 165,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "protocols": ["wifi-mgmt"],
            "payload_contains": ["802.11 assoc-req", "802.11 reassoc-req", "802.11 assoc-resp", "802.11 reassoc-resp"],
        },
        "action": {"tag": "wifi-client-association", "label": "WiFi client association", "severity": "info"},
    },
    {
        "id": "builtin-wifi-action-frame",
        "name": "WiFi action frame",
        "description": "802.11 action frame (spectrum management, block-ack setup, BSS transition, etc.) - mostly protocol housekeeping, occasionally abused by attack tooling (e.g. forced BSS transition).",
        "enabled": True,
        "priority": 166,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["wifi-mgmt"], "payload_contains": ["802.11 action"]},
        "action": {"tag": "wifi-action-frame", "label": "WiFi action frame", "severity": "info"},
    },
    # --- ICS/SCADA (Modbus/TCP, DNP3) ---
    {
        "id": "builtin-modbus-write-command",
        "name": "Modbus write command",
        "description": "A Modbus write function code (write single/multiple coil or register, mask write, or a combined read/write) - the source is changing physical process state on an ICS device, the single highest-value signal a passive Modbus monitor can surface.",
        "enabled": True,
        "priority": 170,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["modbus"], "payload_contains": ["(write)"]},
        "action": {"tag": "modbus-write-command", "label": "Modbus write command", "severity": "high"},
    },
    {
        "id": "builtin-modbus-traffic-seen",
        "name": "Modbus traffic seen",
        "description": "Any Modbus/TCP traffic (port 502) - visibility into ICS activity on the network, not just writes.",
        "enabled": True,
        "priority": 171,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["modbus"], "min_length": 1},
        "action": {"tag": "modbus-traffic", "label": "Modbus traffic", "severity": "info"},
    },
    {
        "id": "builtin-dnp3-restart-command",
        "name": "DNP3 cold/warm restart command",
        "description": "A DNP3 outstation is being remotely cold- or warm-restarted (function codes 13/14) - rarely benign; a common DoS/disruption technique against ICS outstations.",
        "enabled": True,
        "priority": 172,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["dnp3"], "payload_contains": ["cold-restart", "warm-restart"]},
        "action": {"tag": "dnp3-restart-command", "label": "DNP3 restart command", "severity": "critical"},
    },
    {
        "id": "builtin-dnp3-unsolicited-response",
        "name": "DNP3 unsolicited response",
        "description": "A DNP3 outstation pushed data without being polled (function code 130) - normal in some deployments, but a burst from a device that never does this is a known DNP3 attack/DoS pattern.",
        "enabled": True,
        "priority": 173,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["dnp3"], "payload_contains": ["unsolicited-response"]},
        "action": {"tag": "dnp3-unsolicited-response", "label": "DNP3 unsolicited response", "severity": "medium"},
    },
    {
        "id": "builtin-dnp3-traffic-seen",
        "name": "DNP3 traffic seen",
        "description": "Any DNP3 traffic (port 20000) - visibility into ICS activity on the network.",
        "enabled": True,
        "priority": 174,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["dnp3"], "min_length": 1},
        "action": {"tag": "dnp3-traffic", "label": "DNP3 traffic", "severity": "info"},
    },
    {
        "id": "builtin-dhcp-rogue-server",
        "name": "DHCP rogue server",
        "description": "Stateful: flags more than one distinct source IP handing out DHCP leases - a classic rogue/unauthorized DHCP server signature, visible even without WiFi monitor mode since DHCP is broadcast on the local segment.",
        "enabled": True,
        "priority": 175,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["dhcp"]},
        "action": {"tag": "dhcp-rogue-server", "label": "DHCP rogue server", "severity": "critical"},
    },
    # --- Infrastructure/management protocols (SNMP, Syslog, TFTP, RADIUS, MQTT) ---
    {
        "id": "builtin-snmp-weak-community",
        "name": "SNMP default/weak community string",
        "description": "SNMPv1/v2c community string sent in cleartext matches a well-known default ('public', 'private', 'community') - SNMP's entire access control for v1/v2c, exposed on the wire.",
        "enabled": True,
        "priority": 180,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "protocols": ["snmp"],
            "payload_contains": ["community='public'", "community='private'", "community='community'"],
        },
        "action": {"tag": "snmp-weak-community", "label": "SNMP weak community string", "severity": "high"},
    },
    {
        "id": "builtin-snmp-traffic-seen",
        "name": "SNMP traffic seen",
        "description": "Any SNMP traffic (ports 161/162) - visibility into device management activity on the network.",
        "enabled": True,
        "priority": 181,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["snmp"], "min_length": 1},
        "action": {"tag": "snmp-traffic", "label": "SNMP traffic", "severity": "info"},
    },
    {
        "id": "builtin-syslog-high-severity",
        "name": "Syslog high-severity message",
        "description": "A syslog message (port 514) at emergency/alert/critical severity - visibility into what devices on the network are actively reporting as broken.",
        "enabled": True,
        "priority": 182,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "protocols": ["syslog"],
            "payload_contains": ["severity=emergency", "severity=alert", "severity=critical"],
        },
        "action": {"tag": "syslog-high-severity", "label": "Syslog high-severity message", "severity": "medium"},
    },
    {
        "id": "builtin-tftp-file-transfer",
        "name": "TFTP file transfer",
        "description": "A TFTP read/write request (port 69) - TFTP has no authentication or encryption; common for network-gear firmware/config transfer, also abused to plant tampered firmware.",
        "enabled": True,
        "priority": 183,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tftp"], "payload_contains": ["RRQ", "WRQ"]},
        "action": {"tag": "tftp-file-transfer", "label": "TFTP file transfer", "severity": "medium"},
    },
    {
        "id": "builtin-radius-traffic-seen",
        "name": "RADIUS traffic seen",
        "description": "Any RADIUS traffic (ports 1812/1813) - AAA/network-login activity visibility. Passwords in RADIUS are always hashed, so this is metadata-only (NAS IP, username), not credential exposure.",
        "enabled": True,
        "priority": 184,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["radius"], "min_length": 1},
        "action": {"tag": "radius-traffic", "label": "RADIUS traffic", "severity": "info"},
    },
    {
        "id": "builtin-mqtt-cleartext-credentials",
        "name": "MQTT cleartext credentials",
        "description": "An MQTT CONNECT packet (port 1883) carries a username/password - IoT brokers frequently ship without TLS, exposing device credentials on the wire.",
        "enabled": True,
        "priority": 185,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["mqtt"], "payload_contains": ["password=<present>"]},
        "action": {"tag": "mqtt-cleartext-credentials", "label": "MQTT cleartext credentials", "severity": "high"},
    },
    {
        "id": "builtin-mqtt-traffic-seen",
        "name": "MQTT traffic seen",
        "description": "Any MQTT traffic (port 1883) - visibility into IoT device activity on the network.",
        "enabled": True,
        "priority": 186,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["mqtt"], "min_length": 1},
        "action": {"tag": "mqtt-traffic", "label": "MQTT traffic", "severity": "info"},
    },
    # --- Recent (2023-2024) mass-exploited CVEs with a simple, low-false-positive string signature ---
    {
        "id": "builtin-cve-2024-1709-screenconnect",
        "name": "ConnectWise ScreenConnect auth bypass (CVE-2024-1709)",
        "description": "Request targets /SetupWizard.aspx/ on what should be an already-configured instance - a .NET path-parsing quirk (CVE-2024-1709, CVSS 10) lets an attacker reach the setup wizard and create an admin account.",
        "enabled": True,
        "priority": 190,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"/setupwizard\.aspx/"]},
        "action": {"tag": "cve-2024-1709-screenconnect", "label": "ScreenConnect auth bypass (CVE-2024-1709)", "severity": "critical"},
    },
    {
        "id": "builtin-cve-2024-21887-ivanti",
        "name": "Ivanti Connect Secure path traversal (CVE-2023-46805 / CVE-2024-21887)",
        "description": "The exact path-traversal payload observed in mass, nation-state exploitation of chained Ivanti Connect Secure/Policy Secure auth-bypass + command-injection zero-days.",
        "enabled": True,
        "priority": 191,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"api/v1/totp/user-backup-code/\.\./"]},
        "action": {"tag": "cve-2024-21887-ivanti", "label": "Ivanti Connect Secure path traversal (CVE-2023-46805/CVE-2024-21887)", "severity": "critical"},
    },
    # --- Parser coverage gaps: traffic the sniffer can't classify or parse ---
    {
        "id": "builtin-unknown-protocol",
        "name": "Unknown protocol traffic",
        "description": "A recognized Ethernet/IP structure carried a protocol number or EtherType this sniffer doesn't have a dedicated parser for (proto='unknown'). Not malformed - just unclassified.",
        "enabled": True,
        "priority": 195,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["unknown"], "min_length": 1},
        "action": {"tag": "unknown-protocol", "label": "Unknown protocol traffic", "severity": "high"},
    },
    {
        "id": "builtin-unparseable-packet",
        "name": "Unparseable packet",
        "description": "A frame that either raised an exception while being parsed, or was too short/malformed to even attempt (proto='unparseable') - distinct from 'unknown protocol', which means a recognized structure with an unrecognized protocol number. Worth a look: malformed frames are a common fuzzing/exploit-attempt signature.",
        "enabled": True,
        "priority": 196,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["unparseable"], "min_length": 1},
        "action": {"tag": "unparseable-packet", "label": "Unparseable packet", "severity": "high"},
    },
    # --- Sensitive data exposure (PII / secrets in cleartext traffic) ---
    {
        "id": "builtin-sensitive-credit-card",
        "name": "Credit card number exposed",
        "description": "Visa/MasterCard/Amex/Discover-shaped number sequence seen in cleartext traffic.",
        "enabled": True,
        "priority": 200,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
            ]
        },
        "action": {"tag": "sensitive-credit-card", "label": "Credit card exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-ssn",
        "name": "US SSN exposed",
        "description": "US Social Security Number-shaped sequence (###-##-####) seen in cleartext traffic.",
        "enabled": True,
        "priority": 201,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b\d{3}-\d{2}-\d{4}\b"]},
        "action": {"tag": "sensitive-ssn", "label": "SSN exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-private-key",
        "name": "Private key material exposed",
        "description": "PEM-encoded private key header (RSA/EC/DSA/OpenSSH/PGP) seen in cleartext traffic.",
        "enabled": True,
        "priority": 202,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"]},
        "action": {"tag": "sensitive-private-key", "label": "Private key exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-aws-key",
        "name": "AWS access key exposed",
        "description": "AWS access key ID pattern (AKIA...) seen in cleartext traffic.",
        "enabled": True,
        "priority": 203,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\bAKIA[0-9A-Z]{16}\b"]},
        "action": {"tag": "sensitive-aws-key", "label": "AWS key exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-jwt",
        "name": "JWT token exposed",
        "description": "JSON Web Token (header.payload.signature) seen in cleartext traffic.",
        "enabled": True,
        "priority": 204,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\beyj[a-z0-9_-]{10,}\.eyj[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\b"]},
        "action": {"tag": "sensitive-jwt", "label": "JWT exposed", "severity": "medium"},
    },
    {
        "id": "builtin-sensitive-api-token",
        "name": "API token exposed",
        "description": "GitHub or Slack API token pattern seen in cleartext traffic.",
        "enabled": True,
        "priority": 205,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(gh[pousr]_[a-z0-9]{36}|xox[baprs]-[0-9a-z-]{10,})\b"]},
        "action": {"tag": "sensitive-api-token", "label": "API token exposed", "severity": "high"},
    },
    {
        "id": "builtin-sensitive-db-connstring",
        "name": "Database credentials in connection string",
        "description": "MongoDB/Postgres/MySQL/Redis connection string with embedded username:password seen in cleartext traffic.",
        "enabled": True,
        "priority": 206,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(mongodb|postgres(?:ql)?|mysql|redis)://[^:/\s]+:[^@/\s]+@"]},
        "action": {"tag": "sensitive-db-connstring", "label": "DB credentials exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-crypto-wallet",
        "name": "Cryptocurrency wallet address exposed",
        "description": "Bitcoin (legacy/bech32) or Ethereum wallet address seen in cleartext traffic — useful for spotting ransom demands or payout addresses.",
        "enabled": True,
        "priority": 207,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-f0-9]{40})\b"]},
        "action": {"tag": "sensitive-crypto-wallet", "label": "Crypto wallet address exposed", "severity": "medium"},
    },
    {
        "id": "builtin-sensitive-cloud-api-key",
        "name": "Cloud provider API key exposed",
        "description": "Google Cloud/Firebase (AIza...) or Stripe live secret key (sk_live_...) pattern seen in cleartext traffic.",
        "enabled": True,
        "priority": 208,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(aiza[0-9a-z_-]{35}|sk_live_[0-9a-z]{16,})\b"]},
        "action": {"tag": "sensitive-cloud-api-key", "label": "Cloud API key exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-ntlm-auth",
        "name": "NTLM/Negotiate auth exposed",
        "description": "HTTP WWW-Authenticate/Authorization header advertising NTLM or Negotiate (Windows integrated auth) — the handshake is crackable offline if captured.",
        "enabled": True,
        "priority": 209,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"(www-authenticate|authorization):\s*(ntlm|negotiate)\b"]},
        "action": {"tag": "sensitive-ntlm-auth", "label": "NTLM/Negotiate auth exposed", "severity": "medium"},
    },
    # --- Tor / anonymization network usage ---
    {
        "id": "builtin-tor-ports",
        "name": "Tor network ports",
        "description": "Traffic on well-known Tor OR/directory/SOCKS ports.",
        "enabled": True,
        "priority": 210,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [9001, 9030, 9040, 9050, 9051, 9150]},
        "action": {"tag": "tor-port", "label": "Tor network traffic", "severity": "medium"},
    },
    {
        "id": "builtin-tor-onion-domain",
        "name": ".onion domain reference",
        "description": "A Tor hidden-service (.onion) address seen in DNS/HTTP/mDNS/LLMNR traffic.",
        "enabled": True,
        "priority": 211,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b[a-z2-7]{16,56}\.onion\b"]},
        "action": {"tag": "tor-onion-domain", "label": "Tor .onion address", "severity": "medium"},
    },
    # --- Suspicious / high-risk domains (heuristic, no external blocklist feed) ---
    {
        "id": "builtin-suspicious-tld",
        "name": "High-abuse TLD",
        "description": "DNS/HTTP traffic referencing a TLD commonly abused for phishing/malware distribution (heuristic, not a live threat-intel feed).",
        "enabled": True,
        "priority": 220,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\.(xyz|top|club|work|zip|mov|country|gq|cf|tk|ml|ga|icu|rest|monster)\b"]},
        "action": {"tag": "suspicious-tld", "label": "High-abuse TLD", "severity": "low"},
    },
    {
        "id": "builtin-domain-typosquat-pattern",
        "name": "Typosquat-shaped domain",
        "description": "Multi-hyphen domain name shape commonly used in typosquatting/phishing campaigns (e.g. brand-login-secure.com).",
        "enabled": True,
        "priority": 221,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.(com|net|info|biz|org)\b"]},
        "action": {"tag": "domain-typosquat-pattern", "label": "Typosquat-shaped domain", "severity": "low"},
    },
    # --- Web attacks (Suricata WEB-ATTACKS/EXPLOIT-inspired signatures) ---
    {
        "id": "builtin-path-traversal",
        "name": "Path traversal attempt",
        "description": "Directory traversal sequence (../, encoded or double-encoded) seen in request traffic.",
        "enabled": True,
        "priority": 230,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"(\.\.[\\/]){2,}|%2e%2e%2f|%252e%252e%252f"]},
        "action": {"tag": "path-traversal", "label": "Path traversal attempt", "severity": "high"},
    },
    {
        "id": "builtin-command-injection",
        "name": "Command injection attempt",
        "description": "Shell metacharacter sequence commonly used for OS command injection.",
        "enabled": True,
        "priority": 231,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r";\s*(cat|wget|curl|nc|bash|sh|python|perl)\s|\$\([^)]+\)|`[^`]+`"]},
        "action": {"tag": "command-injection", "label": "Command injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-log4shell",
        "name": "Log4Shell / JNDI injection",
        "description": "${jndi:...} lookup pattern seen in traffic — the Log4Shell (CVE-2021-44228) exploitation signature.",
        "enabled": True,
        "priority": 232,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\$\{jndi:(ldap|rmi|dns|iiop|corba|nis)://"]},
        "action": {"tag": "log4shell", "label": "Log4Shell / JNDI injection", "severity": "critical"},
    },
    {
        "id": "builtin-shellshock",
        "name": "Shellshock exploitation attempt",
        "description": "Bash function-definition-in-environment-variable pattern (CVE-2014-6271) seen in traffic.",
        "enabled": True,
        "priority": 233,
        "source": "builtin",
        "mode": "rule",
        "match": {"payload_contains": ["() { :;"]},
        "action": {"tag": "shellshock", "label": "Shellshock attempt", "severity": "critical"},
    },
    {
        "id": "builtin-xxe-injection",
        "name": "XXE injection attempt",
        "description": "XML external entity declaration (<!ENTITY ... SYSTEM) seen in request traffic — used to read local files or trigger SSRF via a vulnerable XML parser.",
        "enabled": True,
        "priority": 234,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"<!entity\s+\S+\s+system\s+[\"']"]},
        "action": {"tag": "xxe-injection", "label": "XXE injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-ssrf-attempt",
        "name": "SSRF probe attempt",
        "description": "Request targeting a non-HTTP internal scheme (file/gopher/dict) or the cloud instance-metadata address — a common server-side request forgery signature.",
        "enabled": True,
        "priority": 235,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(file|gopher|dict)://|169\.254\.169\.254|metadata\.google\.internal"]},
        "action": {"tag": "ssrf-attempt", "label": "SSRF probe attempt", "severity": "high"},
    },
    {
        "id": "builtin-ssti-attempt",
        "name": "Server-side template injection attempt",
        "description": "Template-expression probe pattern (e.g. {{7*7}}, ${7*7}) commonly used to fingerprint SSTI-vulnerable template engines.",
        "enabled": True,
        "priority": 236,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\}"]},
        "action": {"tag": "ssti-attempt", "label": "SSTI attempt", "severity": "medium"},
    },
    {
        "id": "builtin-insecure-deserialization",
        "name": "Insecure deserialization payload",
        "description": "Java (rO0AB... base64 magic bytes) or PHP (O:8:\"stdClass\":...) serialized-object signature seen in request traffic.",
        "enabled": True,
        "priority": 237,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"ro0ab[a-z0-9+/=]{6,}|o:\d+:\"[a-z0-9_\\]+\":\d+:\{"]},
        "action": {"tag": "insecure-deserialization", "label": "Insecure deserialization payload", "severity": "high"},
    },
    {
        "id": "builtin-webshell-reference",
        "name": "Known web shell reference",
        "description": "Filename or marker matching a well-known PHP/ASP web shell (c99, r57, b374k, wso, weevely) seen in request traffic.",
        "enabled": True,
        "priority": 238,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(c99|r57|b374k|wso|weevely)(shell)?\b"]},
        "action": {"tag": "webshell-reference", "label": "Web shell reference", "severity": "critical"},
    },
    {
        "id": "builtin-nosql-injection",
        "name": "NoSQL injection pattern",
        "description": "MongoDB query-operator injection pattern ($where/$ne/$gt as a JSON key) seen in request traffic.",
        "enabled": True,
        "priority": 239,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\{\s*\"\$(where|ne|gt|regex)\"\s*:"]},
        "action": {"tag": "nosql-injection", "label": "NoSQL injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-crlf-injection",
        "name": "CRLF / HTTP response-splitting attempt",
        "description": "Encoded or literal CRLF sequence injected into a request, used for HTTP response splitting or header/cookie injection.",
        "enabled": True,
        "priority": 243,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"%0d%0a(set-cookie|location):|\r\nset-cookie:"]},
        "action": {"tag": "crlf-injection", "label": "CRLF injection attempt", "severity": "medium"},
    },
    {
        "id": "builtin-ldap-injection",
        "name": "LDAP injection pattern",
        "description": "LDAP search-filter injection pattern (wildcard/always-true filter) seen in request traffic.",
        "enabled": True,
        "priority": 244,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\(\s*\|\s*\(.*=\*\)\)|\(\s*&\s*\(.*=\*\)\)"]},
        "action": {"tag": "ldap-injection", "label": "LDAP injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-struts2-ognl-injection",
        "name": "Struts2 OGNL injection attempt",
        "description": "OGNL expression invoking Runtime.exec via a Content-Type/parameter, the CVE-2017-5638-style Apache Struts2 exploitation signature.",
        "enabled": True,
        "priority": 245,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"%\{.*getruntime\(\).*exec|ognl\.ognlcontext"]},
        "action": {"tag": "struts2-ognl-injection", "label": "Struts2 OGNL injection attempt", "severity": "critical"},
    },
    {
        "id": "builtin-spring4shell-attempt",
        "name": "Spring4Shell exploitation attempt",
        "description": "class.module.classLoader parameter-pollution pattern seen in request traffic — the Spring4Shell (CVE-2022-22965) exploitation signature.",
        "enabled": True,
        "priority": 246,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"class\.module\.classloader"]},
        "action": {"tag": "spring4shell-attempt", "label": "Spring4Shell attempt", "severity": "critical"},
    },
    # --- Policy violations (Suricata POLICY-inspired) ---
    {
        "id": "builtin-p2p-bittorrent",
        "name": "BitTorrent / P2P traffic",
        "description": "BitTorrent peer-wire protocol handshake seen in traffic.",
        "enabled": True,
        "priority": 240,
        "source": "builtin",
        "mode": "rule",
        "match": {"payload_contains": ["BitTorrent protocol"]},
        "action": {"tag": "p2p-bittorrent", "label": "BitTorrent traffic", "severity": "low"},
    },
    {
        "id": "builtin-crypto-mining",
        "name": "Cryptocurrency mining (Stratum)",
        "description": "Stratum mining-pool protocol messages seen in traffic — cryptojacking/unauthorized mining signal.",
        "enabled": True,
        "priority": 241,
        "source": "builtin",
        "mode": "rule",
        "match": {"payload_contains": ["mining.subscribe", "mining.notify", "mining.authorize"]},
        "action": {"tag": "crypto-mining", "label": "Cryptomining traffic", "severity": "high"},
    },
    {
        "id": "builtin-suspicious-user-agent",
        "name": "Known scanner/attack-tool user agent",
        "description": "HTTP User-Agent header matching a well-known scanning/exploitation tool (sqlmap, Nikto, Nmap, masscan, etc.).",
        "enabled": True,
        "priority": 242,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"user-agent:\s*[^\r\n]*(sqlmap|nikto|nmap|masscan|zgrab|metasploit|dirbuster|gobuster|wpscan"
                r"|whatweb|acunetix|nessus|openvas|qualys|burpsuite|hydra|nuclei|ffuf|feroxbuster)"
            ]
        },
        "action": {"tag": "suspicious-user-agent", "label": "Scanner tool user agent", "severity": "high"},
    },
    # --- Malware / C2 / botnet activity ---
    {
        "id": "builtin-eicar-test-string",
        "name": "EICAR antivirus test string",
        "description": "The standardized EICAR test file signature — not real malware, but its presence in traffic confirms AV/content-inspection is (or isn't) actually scanning the stream.",
        "enabled": True,
        "priority": 250,
        "source": "builtin",
        "mode": "rule",
        "match": {"payload_contains": ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"]},
        "action": {"tag": "eicar-test-string", "label": "EICAR test string", "severity": "info"},
    },
    {
        "id": "builtin-iot-default-credentials",
        "name": "IoT/Telnet default credential attempt",
        "description": "Common factory-default username:password pair (admin/admin, root/12345, etc.) attempted over Telnet — the classic Mirai-family IoT botnet infection signature.",
        "enabled": True,
        "priority": 251,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "protocols": ["tcp"],
            "ports": [23],
            "payload_regex": [r"\b(admin|root|support|user|guest|default):(admin|root|12345|123456|password|default|guest|1234|toor)\b"],
        },
        "action": {"tag": "iot-default-credentials", "label": "IoT default credential attempt", "severity": "critical"},
    },
    {
        "id": "builtin-ransomware-note-language",
        "name": "Ransomware note language",
        "description": "Phrasing characteristic of a ransomware ransom note (files encrypted + payment demand) seen in cleartext traffic.",
        "enabled": True,
        "priority": 252,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"your (files|documents|data)\s+(have been|were|has been)\s+encrypted",
                r"decrypt.{0,30}(bitcoin|btc|monero|xmr)",
            ]
        },
        "action": {"tag": "ransomware-note-language", "label": "Ransomware note language", "severity": "critical"},
    },
    {
        "id": "builtin-crypto-mining-pool-domain",
        "name": "Cryptomining pool domain reference",
        "description": "DNS/HTTP traffic referencing a well-known public cryptocurrency mining pool — unauthorized/cryptojacking signal distinct from the raw Stratum protocol check.",
        "enabled": True,
        "priority": 253,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b[a-z0-9.-]*(minexmr|nanopool|ethermine|f2pool|antpool|2miners|supportxmr)\.[a-z]{2,}\b"]},
        "action": {"tag": "crypto-mining-pool-domain", "label": "Cryptomining pool domain", "severity": "medium"},
    },
    # --- Phishing ---
    {
        "id": "builtin-phishing-urgency-language",
        "name": "Phishing urgency/credential-harvest language",
        "description": "Account-verification urgency phrasing (verify/confirm/suspended + immediately/24 hours) commonly used in phishing lures.",
        "enabled": True,
        "priority": 260,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(verify|confirm|re-?validate)\b[^.]{0,25}\b(your\s+)?(account|password|identity)\b[^.]{0,25}\b(immediately|urgent(ly)?|24\s*hours|suspend(ed)?)\b"
            ]
        },
        "action": {"tag": "phishing-urgency-language", "label": "Phishing urgency language", "severity": "medium"},
    },
    {
        "id": "builtin-punycode-domain",
        "name": "Punycode/IDN homograph domain",
        "description": "xn-- (punycode) encoded domain label — a common technique for homograph/lookalike-domain phishing.",
        "enabled": True,
        "priority": 261,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\bxn--[a-z0-9-]+\b"]},
        "action": {"tag": "punycode-domain", "label": "Punycode/IDN domain", "severity": "low"},
    },
    # --- Reconnaissance (Suricata SCAN-inspired, stateful) ---
    {
        "id": "builtin-port-scan",
        "name": "Port scan / reconnaissance",
        "description": "Stateful: flags a source touching many distinct destination ports within a short window.",
        "enabled": True,
        "priority": 5,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["tcp", "udp"]},
        "action": {"tag": "port-scan", "label": "Port scan detected", "severity": "high"},
    },
    # --- Restricted / acceptable-use content categories ---
    # Distinct from the security-threat categories above: these flag access
    # to content categories commonly restricted by acceptable-use policy
    # (parental controls, corporate DLP/compliance, honeypot/threat-intel
    # analysis of what an attacker or a monitored host is reaching for) —
    # tagged "policy-*" rather than a security severity class. Detection is
    # deliberately shape/keyword/label-based only (the same technique real
    # DNS/URL content filters use), never content generation: no explicit,
    # graphic, or instructional material is included or produced here.
    {
        "id": "builtin-policy-adult-content-label",
        "name": "Adult-content self-label (RTA) detected",
        "description": "The industry-standard RTA (\"Restricted To Adults\", ICRA/ASACP) self-rating label, which adult sites are expected to publish specifically so content filters can detect them.",
        "enabled": True,
        "priority": 300,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"rta-5042-1996-1400-1577-rta"]},
        "action": {"tag": "policy-adult-content", "label": "Adult content (RTA label)", "severity": "medium"},
    },
    {
        "id": "builtin-policy-adult-content-domain",
        "name": "Adult-content domain heuristic",
        "description": "Hostname containing a common adult-industry keyword (heuristic domain-shape match, the same technique DNS/URL content filters use — not a curated site list).",
        "enabled": True,
        "priority": 301,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b[a-z0-9-]*(porn|xxx|nsfw)[a-z0-9-]*\.(com|net|org|xxx|tv|cam|to|io)\b"]},
        "action": {"tag": "policy-adult-content", "label": "Adult content (domain heuristic)", "severity": "low"},
    },
    {
        "id": "builtin-policy-weapons-marketplace",
        "name": "Weapons marketplace language",
        "description": "Commerce-context language for firearms/ammunition/suppressors (buy/sell/ship + weapon term) seen in cleartext traffic — a policy/compliance signal, not a technical exploitation risk.",
        "enabled": True,
        "priority": 302,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(buy|sell|selling|ship(ping)?)\b[^.\r\n]{0,25}\b(firearms?|handguns?|pistols?|rifles?|shotguns?|ammunition|ammo|silencers?|suppressors?)\b",
                r"\b(guns?|firearms?|weapons?)\s+for\s+sale\b",
            ]
        },
        "action": {"tag": "policy-weapons-content", "label": "Weapons marketplace language", "severity": "high"},
    },
    {
        "id": "builtin-policy-drugs-marketplace",
        "name": "Illegal drug marketplace language",
        "description": "Commerce-context language for controlled substances (drug name + sale/quantity/pricing term) seen in cleartext traffic — commonly seen in darknet-market traffic.",
        "enabled": True,
        "priority": 303,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(cocaine|heroin|fentanyl|methamphetamine|crystal meth|mdma|ecstasy|lsd)\b[^.\r\n]{0,25}\b(for sale|kilo|kg|gram|grams|ounce|price|shipping|stealth)\b",
                r"\bdark ?net market\b",
            ]
        },
        "action": {"tag": "policy-drugs-content", "label": "Drug marketplace language", "severity": "high"},
    },
    {
        "id": "builtin-policy-fraud-carding",
        "name": "Stolen payment data marketplace language",
        "description": "Carding-forum jargon (CVV/fullz/dumps + sale/pricing term) seen in cleartext traffic — stolen-payment-data marketplace signal.",
        "enabled": True,
        "priority": 304,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(cvv2?|fullz|dumps\+pin|dumps)\b[^.\r\n]{0,20}\b(for sale|price|\$\d)\b",
                r"\bcarding\b[^.\r\n]{0,15}\b(forum|tutorial|method)\b",
            ]
        },
        "action": {"tag": "policy-fraud-content", "label": "Stolen payment data marketplace", "severity": "high"},
    },
    {
        "id": "builtin-policy-unlicensed-gambling",
        "name": "Unlicensed gambling marketplace language",
        "description": "Offshore/unlicensed online-gambling promotional language (casino/sportsbook + deposit-bonus/no-verification term) seen in cleartext traffic.",
        "enabled": True,
        "priority": 305,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(casino|sportsbook|online poker)\b[^.\r\n]{0,20}\b(deposit bonus|no.?verification|no.?kyc)\b"
            ]
        },
        "action": {"tag": "policy-gambling-content", "label": "Unlicensed gambling language", "severity": "low"},
    },
]


def _default_monitor_path() -> Path:
    return resolve_data_file("default_monitors.json")


def load_builtin_monitors() -> list[dict]:
    path = _default_monitor_path()
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                return [normalize_monitor(item, allow_source=True) for item in payload if isinstance(item, dict)]
        except Exception:
            pass
    return [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]


def _validate_match_not_empty(match: dict):
    criteria_keys = (
        "protocols",
        "ip_versions",
        "eth_types",
        "ports",
        "src_ports",
        "dst_ports",
        "payload_contains",
        "payload_prefix_hex",
        "payload_regex",
    )
    has_list_criteria = any(match.get(key) for key in criteria_keys)
    has_length_criteria = bool(match.get("min_length")) or bool(match.get("max_length"))
    if not has_list_criteria and not has_length_criteria:
        raise ValueError("Monitor match must include at least one condition")


def _validate_regex_patterns(match: dict):
    for pattern in match.get("payload_regex", []):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern '{pattern}': {exc}") from exc


def normalize_monitor(item: dict, allow_source: bool = False) -> dict:
    data = item if isinstance(item, dict) else {}
    rule_id = str(data.get("id") or data.get("slug") or data.get("name") or "").strip()
    if not rule_id:
        rule_id = "custom-monitor"
    name = str(data.get("name") or rule_id).strip() or rule_id
    description = str(data.get("description") or "").strip()
    enabled = bool(data.get("enabled", True))
    priority = safe_int(data.get("priority", 100), 100)
    match = normalize_match(data.get("match") if isinstance(data.get("match"), dict) else {})
    mode = str(data.get("mode") or "").strip().lower()
    if mode not in {"rule", "regex", "stateful"}:
        mode = "regex" if match.get("payload_regex") and not any(
            match.get(key)
            for key in ("protocols", "ip_versions", "eth_types", "ports", "src_ports", "dst_ports", "payload_contains", "payload_prefix_hex")
        ) else "rule"

    _validate_match_not_empty(match)
    _validate_regex_patterns(match)

    normalized = {
        "id": rule_id,
        "name": name,
        "description": description,
        "enabled": enabled,
        "priority": priority,
        "mode": mode,
        "match": match,
        "action": normalize_action(data.get("action") if isinstance(data.get("action"), dict) else {}),
    }
    if allow_source:
        normalized["source"] = str(data.get("source") or "custom").strip() or "custom"
    return normalized


def monitor_matches_packet(monitor: dict, packet: dict) -> bool:
    return rule_matches_packet(monitor, packet)


def evaluate_packet(packet: dict, monitors: list[dict]) -> list[dict]:
    matches = []
    for monitor in sorted(monitors, key=lambda item: (safe_int(item.get("priority", 100), 100), str(item.get("name") or ""))):
        if str(monitor.get("mode") or "").strip().lower() == "stateful":
            # Stateful monitors have no declarative match logic to evaluate here —
            # they're driven by anomaly.AnomalyEngine, which runs separately and
            # unconditionally in Sniffer._store_packet.
            continue
        try:
            if not monitor_matches_packet(monitor, packet):
                continue
        except Exception:
            continue
        action = monitor.get("action") if isinstance(monitor.get("action"), dict) else {}
        matches.append(
            {
                "monitor_id": monitor.get("id"),
                "monitor_name": monitor.get("name"),
                "tag": action.get("tag") or monitor.get("id"),
                "label": action.get("label") or monitor.get("name"),
                "severity": action.get("severity") or "info",
            }
        )
    return matches


def describe_match(monitor: dict, packet: dict) -> str:
    """Best-effort description of the specific value that made this packet match the monitor."""
    match = monitor.get("match") if isinstance(monitor.get("match"), dict) else {}
    domain = str(packet.get("domain") or "").strip()
    domain_source = str(packet.get("domain_source") or "").strip()

    regexes = [str(item).strip() for item in match.get("payload_regex", []) if str(item).strip()]
    if regexes:
        packet_text = build_packet_text(packet)
        for pattern in regexes:
            try:
                found = re.search(pattern, packet_text, re.IGNORECASE)
            except re.error:
                continue
            if found:
                value = found.group(0).strip()
                if value:
                    return value[:120]
        if domain:
            return domain

    if domain and domain_source:
        return domain

    http_path = str(packet.get("http_path") or "").strip()
    if http_path and match.get("payload_contains"):
        return http_path

    needles = [str(item) for item in match.get("payload_contains", []) if str(item).strip()]
    if needles:
        packet_text = build_packet_text(packet)
        for needle in needles:
            if needle.lower() in packet_text:
                return needle.strip()

    prefix_hex = [str(item) for item in match.get("payload_prefix_hex", []) if str(item).strip()]
    if prefix_hex:
        return f"payload starts 0x{prefix_hex[0]}"

    ports = [safe_int(item, 0) for item in match.get("ports", []) if safe_int(item, 0)]
    if ports:
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        if dst_port in ports:
            return f"port {dst_port}"
        if src_port in ports:
            return f"port {src_port}"

    eth_types = [safe_int(item, 0) for item in match.get("eth_types", []) if safe_int(item, 0)]
    if eth_types:
        return f"eth 0x{safe_int(packet.get('eth_type', 0), 0):04x}"

    protocols = [normalize_protocol_name(item) for item in match.get("protocols", []) if str(item).strip()]
    if protocols:
        return normalize_protocol_name(packet.get("proto"))

    min_length = safe_int(match.get("min_length", 0), 0)
    if min_length:
        return f"length {safe_int(packet.get('length', 0), 0)}B"

    return ""
