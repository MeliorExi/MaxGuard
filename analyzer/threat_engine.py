import os
import json
import requests
from collections import Counter
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


api_key = os.getenv("OPENROUTER_API_KEY")
client = (
    OpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
    )
    if api_key
    else None
)


SEVERITY_SCORES = {
    21:  {"score": 9, "level": "CRITICAL", "name": "FTP"},
    23:  {"score": 10, "level": "CRITICAL", "name": "Telnet"},
    80:  {"score": 7,  "level": "HIGH",     "name": "HTTP"},
    143: {"score": 6,  "level": "HIGH",     "name": "IMAP"},
    110: {"score": 6,  "level": "HIGH",     "name": "POP3"},
    3389:{"score": 8,  "level": "CRITICAL", "name": "RDP"},
    8080:{"score": 5,  "level": "MEDIUM",   "name": "HTTP-Alt"},
}

DEVICE_SIGNATURES = {
    "192.168.": "Internal network device",
    "10.":      "Internal network device",
    "172.16.":  "Internal network device",
    "224.":     "Multicast address",
    "239.":     "Multicast address",
    "8.8.8.":   "Google DNS server",
    "8.8.4.":   "Google DNS server",
    "1.1.1.":   "Cloudflare DNS server",
    "140.82.":  "GitHub server",
    "23.44.":   "Akamai CDN server",
    "104.":     "Cloud provider (likely Microsoft/Akamai)",
    "18.":      "Amazon AWS server",
}

INVESTIGATION_GUIDES = {
    "FTP": {
        "what_it_is": "FTP (File Transfer Protocol) sends files over the network in plain text. Anyone on the same network can read the files and credentials being transferred.",
        "how_to_investigate": [
            "Identify which device initiated the FTP connection (src_ip)",
            "Check if the destination IP is an authorized internal server",
            "Review what files were being transferred using network logs",
            "Check if FTP is an approved service in your environment",
        ],
        "how_to_fix": [
            "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS",
            "Block port 21 at the firewall for all unauthorized devices",
            "Audit all FTP server configurations and disable anonymous access",
            "Update all file transfer scripts to use encrypted alternatives",
        ],
        "pci_requirement": "PCI-DSS v4.0 Requirement 4.2.1",
    },
    "Telnet": {
        "what_it_is": "Telnet sends all data including usernames and passwords in plain text. It is one of the most dangerous protocols in a retail environment.",
        "how_to_investigate": [
            "Identify which device is using Telnet (src_ip)",
            "Determine if the destination is a managed switch, router, or server",
            "Check device management interfaces for Telnet being enabled",
            "Review access logs on the destination device",
        ],
        "how_to_fix": [
            "Disable Telnet on all network devices immediately",
            "Replace with SSH version 2 for all remote management",
            "Block port 23 at the perimeter and internal firewalls",
            "Audit all network equipment for Telnet service status",
        ],
        "pci_requirement": "PCI-DSS v4.0 Requirement 4.2.1",
    },
    "HTTP": {
        "what_it_is": "HTTP transmits web traffic without encryption. In a retail environment this can expose payment pages, session tokens, and customer data to interception.",
        "how_to_investigate": [
            "Identify which device is making HTTP requests (src_ip)",
            "Check the destination IP to determine what site is being accessed",
            "Review browser history or application logs on the source device",
            "Determine if the HTTP traffic is from a POS system or back-office device",
        ],
        "how_to_fix": [
            "Force HTTPS on all web servers using HTTP to HTTPS redirects",
            "Install valid SSL/TLS certificates on all web-facing services",
            "Implement HTTP Strict Transport Security (HSTS)",
            "Block port 80 outbound at the firewall and redirect to 443",
        ],
        "pci_requirement": "PCI-DSS v4.0 Requirement 4.2.1",
    },
    "RDP": {
        "what_it_is": "RDP (Remote Desktop Protocol) exposed on the network is a major attack vector. It has been exploited in numerous retail breaches to gain direct access to POS systems.",
        "how_to_investigate": [
            "Identify which device has RDP exposed (dst_ip on port 3389)",
            "Check if RDP access is authorized and documented",
            "Review RDP event logs for unauthorized access attempts",
            "Verify if the source IP is an authorized administrator",
        ],
        "how_to_fix": [
            "Disable RDP on all devices where it is not absolutely required",
            "Place RDP behind a VPN so it is not directly accessible",
            "Enable Network Level Authentication (NLA) for all RDP connections",
            "Implement multi-factor authentication for all RDP access",
        ],
        "pci_requirement": "PCI-DSS v4.0 Requirement 1.3.2",
    },
    "IMAP": {
        "what_it_is": "IMAP on port 143 transmits email content and credentials without encryption, potentially exposing sensitive business communications.",
        "how_to_investigate": [
            "Identify which device is using unencrypted IMAP",
            "Check email client configurations on the source device",
            "Review what email server is being accessed",
            "Determine if any cardholder data is transmitted via email",
        ],
        "how_to_fix": [
            "Configure all email clients to use IMAPS (port 993) with SSL/TLS",
            "Block port 143 at the firewall",
            "Update email server settings to require encrypted connections",
            "Enforce TLS for all email communications in the environment",
        ],
        "pci_requirement": "PCI-DSS v4.0 Requirement 4.2.1",
    },
    "POP3": {
        "what_it_is": "POP3 on port 110 retrieves email without encryption, exposing email content and login credentials on the network.",
        "how_to_investigate": [
            "Identify which device is using unencrypted POP3",
            "Check email client configurations on the source device",
            "Determine if sensitive data is being received via this email account",
        ],
        "how_to_fix": [
            "Switch to POP3S (port 995) with SSL/TLS encryption",
            "Block port 110 at the firewall",
            "Consider migrating to IMAP with TLS or a modern email solution",
        ],
        "pci_requirement": "PCI-DSS v4.0 Requirement 4.2.1",
    },
    "HTTP-Alt": {
        "what_it_is": "Port 8080 is commonly used as an alternative HTTP port, often for web proxies or development servers running without encryption.",
        "how_to_investigate": [
            "Identify which application is using port 8080",
            "Check if this is an authorized proxy or application server",
            "Review if any sensitive data is transmitted over this connection",
        ],
        "how_to_fix": [
            "Configure the application to use HTTPS on port 8443 instead",
            "Block port 8080 at the firewall if not required",
            "Review proxy configurations and enforce TLS",
        ],
        "pci_requirement": "PCI-DSS v4.0 Requirement 4.2.1",
    },
}

def fingerprint_device(ip: str) -> str:
    for prefix, description in DEVICE_SIGNATURES.items():
        if ip.startswith(prefix):
            return description
    return "External/unknown host"

def calculate_severity(packets: list) -> dict:
    max_score = 0
    scores = []
    for p in packets:
        if p.get("pci_violation"):
            port = p.get("dst_port") or p.get("src_port")
            if port in SEVERITY_SCORES:
                score = SEVERITY_SCORES[port]["score"]
                scores.append(score)
                max_score = max(max_score, score)

    if not scores:
        return {"overall_score": 0, "level": "NONE", "avg_score": 0}

    avg_score = round(sum(scores) / len(scores), 1)

    if max_score >= 9:
        level = "CRITICAL"
    elif max_score >= 7:
        level = "HIGH"
    elif max_score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "overall_score": max_score,
        "avg_score": avg_score,
        "level": level
    }

def analyze_traffic_patterns(packets: list) -> dict:
    if not packets:
        return {}

    src_ips = Counter(p["src_ip"] for p in packets if p.get("src_ip"))
    dst_ips = Counter(p["dst_ip"] for p in packets if p.get("dst_ip"))
    protocols = Counter(p["protocol"] for p in packets if p.get("protocol"))
    dst_ports = Counter(p["dst_port"] for p in packets if p.get("dst_port"))

    top_talkers = [{"ip": ip, "count": count, "device_type": fingerprint_device(ip)} for ip, count in src_ips.most_common(5)]
    top_destinations = [{"ip": ip, "count": count, "device_type": fingerprint_device(ip)} for ip, count in dst_ips.most_common(5)]
    top_ports = [{"port": port, "count": count} for port, count in dst_ports.most_common(10)]

    violation_ips = set()
    for p in packets:
        if p.get("pci_violation"):
            violation_ips.add(p.get("src_ip"))

    port_scan_suspects = []
    for ip, count in src_ips.items():
        unique_ports = len(set(p["dst_port"] for p in packets if p.get("src_ip") == ip and p.get("dst_port")))
        if unique_ports > 10:
            port_scan_suspects.append({"ip": ip, "unique_ports_scanned": unique_ports})

    return {
        "top_talkers": top_talkers,
        "top_destinations": top_destinations,
        "protocol_distribution": dict(protocols),
        "top_ports": top_ports,
        "violation_source_ips": list(violation_ips),
        "port_scan_suspects": port_scan_suspects,
    }

def get_affected_devices(packets: list) -> list:
    devices = {}
    for p in packets:
        if p.get("pci_violation"):
            ip = p.get("src_ip")
            if ip not in devices:
                devices[ip] = {
                    "ip": ip,
                    "device_type": fingerprint_device(ip),
                    "violations": [],
                    "violation_count": 0,
                }
            if p.get("violation_detail") not in devices[ip]["violations"]:
                devices[ip]["violations"].append(p.get("violation_detail"))
            devices[ip]["violation_count"] += 1

    return sorted(devices.values(), key=lambda x: x["violation_count"], reverse=True)


def analyze_packets_for_threats(packets: list) -> str:
    if not packets:
        return "No packets to analyze."

    violations = [p for p in packets if p.get("pci_violation")]
    total = len(packets)
    total_violations = len(violations)
    severity = calculate_severity(packets)
    patterns = analyze_traffic_patterns(packets)

    # Preserve the threat summary when no cloud API key is configured.
    # Detailed finding explanations are handled separately by local Ollama.
    if client is None:
        return (
            f"Threat level: {severity['level']}\n"
            f"Total packets: {total}\n"
            f"PCI-DSS violations: {total_violations}\n"
            f"Highest severity score: {severity['overall_score']}/10\n"
            "Cloud AI analysis unavailable: OPENROUTER_API_KEY is not set."
        )

    packet_summary = json.dumps(violations[:20], indent=2)

    prompt = f"""You are a PCI-DSS v4.0 security analyst reviewing network scan results from a retail environment.

SCAN SUMMARY:
- Total packets captured: {total}
- Total PCI-DSS violations detected: {total_violations}
- Overall severity score: {severity['overall_score']}/10
- Severity level: {severity['level']}
- Top talkers: {json.dumps(patterns.get('top_talkers', []))}
- Violation source IPs: {patterns.get('violation_source_ips', [])}

VIOLATION DETAILS (up to 20 shown):
{packet_summary}

Provide a structured security analysis with the following sections:

1. THREAT LEVEL: (CRITICAL / HIGH / MEDIUM / LOW / NONE)
2. EXECUTIVE SUMMARY: 3-4 sentences summarizing the security posture for a retail executive.
3. VIOLATIONS FOUND: List each unique violation with the exact PCI-DSS v4.0 requirement number.
4. RISK EXPLANATION: Explain why each violation is dangerous in a retail cardholder data environment.
5. AFFECTED DEVICES: Which devices are most at risk based on the traffic patterns.
6. REMEDIATION STEPS: Specific actionable steps to fix each violation in priority order.
7. COMPLIANCE STATUS: Overall PCI-DSS v4.0 compliance assessment with a pass/fail for each requirement.
8. RECOMMENDED NEXT STEPS: Three immediate actions the security team should take within 24 hours.

Be specific, technical, and professional. Reference exact PCI-DSS v4.0 requirement numbers."""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a PCI-DSS v4.0 QSA specializing in retail network security. Provide precise, actionable, professional analysis suitable for a compliance report."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2,
        max_tokens=2000
    )

    return response.choices[0].message.content


def get_threat_summary(packets: list) -> dict:
    if not packets:
        return {
            "threat_level": "NONE",
            "total_packets": 0,
            "total_violations": 0,
            "violation_types": [],
            "severity": {"overall_score": 0, "level": "NONE", "avg_score": 0},
            "patterns": {},
            "affected_devices": [],
            "investigation_guides": {},
            "analysis": "No packets to analyze."
        }

    violations = [p for p in packets if p.get("pci_violation")]
    violation_types = list(set([
        p["violation_detail"] for p in violations
        if p.get("violation_detail")
    ]))

    severity = calculate_severity(packets)
    patterns = analyze_traffic_patterns(packets)
    affected_devices = get_affected_devices(packets)

    relevant_guides = {}
    for p in violations:
        port = p.get("dst_port") or p.get("src_port")
        if port in SEVERITY_SCORES:
            name = SEVERITY_SCORES[port]["name"]
            if name in INVESTIGATION_GUIDES and name not in relevant_guides:
                relevant_guides[name] = INVESTIGATION_GUIDES[name]

    analysis = analyze_packets_for_threats(packets)

    threat_level = severity["level"]

    return {
        "threat_level": threat_level,
        "total_packets": len(packets),
        "total_violations": len(violations),
        "violation_types": violation_types,
        "severity": severity,
        "patterns": patterns,
        "affected_devices": affected_devices,
        "investigation_guides": relevant_guides,
        "analysis": analysis
    }

if __name__ == "__main__":
    test_packets = [
        {
            "timestamp": "2026-04-20 10:00:01",
            "src_ip": "192.168.1.105",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "src_port": 52341,
            "dst_port": 23,
            "pci_violation": True,
            "violation_detail": "Telnet - Unencrypted remote access (PCI DSS 4.2.1)"
        },
        {
            "timestamp": "2026-04-20 10:00:02",
            "src_ip": "192.168.1.105",
            "dst_ip": "23.44.129.57",
            "protocol": "TCP",
            "src_port": 54231,
            "dst_port": 80,
            "pci_violation": True,
            "violation_detail": "HTTP - Unencrypted web traffic (PCI DSS 4.2.1)"
        },
        {
            "timestamp": "2026-04-20 10:00:03",
            "src_ip": "192.168.1.105",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "src_port": 54232,
            "dst_port": 443,
            "pci_violation": False,
            "violation_detail": None
        }
    ]

    print("Testing Max-Guard Enhanced Threat Engine...")
    result = get_threat_summary(test_packets)
    print(f"THREAT LEVEL: {result['threat_level']}")
    print(f"Severity Score: {result['severity']['overall_score']}/10")
    print(f"Total Violations: {result['total_violations']}")
    print(f"Affected Devices: {result['affected_devices']}")
    print(f"Top Talkers: {result['patterns'].get('top_talkers', [])}")
    print(f"\nFULL ANALYSIS:\n{result['analysis']}")
