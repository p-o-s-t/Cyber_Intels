# Intelligence Injects for Cybersecurity Exercise

## Inject 1: Initial Discovery (HydroPhantom)
**Timestamp**: T+00:15

**Source**: OSINT/Dark Web Monitoring

**Content**: An intelligence report indicates that a state-sponsored actor known as **HydroPhantom** has been observed discussing vulnerabilities in VPN gateways commonly used by water utilities. They are specifically interested in organizations using 'vendor_admin' accounts for remote maintenance.

**ATT&CK - ICS**:
- **T0859 - Valid Accounts**: Use of administrative credentials.
- **TA0102 - Discovery**: Reconnaissance of remote access infrastructure.

## Inject 2: Anomaly Detected (AquaLeak)
**Timestamp**: T+01:00

**Source**: Network IDS/IPS

**Content**: Multiple attempts to connect to TCP Port 20256 (Unitronics PCOM) have been detected originating from a known malicious IP range associated with the **AquaLeak** hacktivist group.

**ATT&CK - ICS**:
- **T0883 - Internet Accessible Device**: Scanning for exposed industrial protocols.
- **TA0108 - Internet Accessible Device**: Initial access via exposed ports.

## Inject 3: Operational Impact (AquaLeak)
**Timestamp**: T+02:30

**Source**: Operator Report

**Content**: The HMI for the Main Pumping Station has been replaced with a static image stating "YOUR WATER IS OURS - AQUALEAK". Local control of the pumps is still possible, but remote visibility and automatic chlorination adjustments have been lost.

**ATT&CK - ICS**:
- **T0829 - Loss of View**: Replacement of HMI graphics.
- **T0814 - Denial of Service**: Disruption of remote control capabilities.

## Inject 4: Deep Persistence (HydroPhantom)
**Timestamp**: T+04:00

**Source**: Forensic Analysis

**Content**: During a routine audit, a non-standard firmware image was detected on a secondary PLC. The firmware contains hidden code that appears to mirror all Modbus traffic to an external IP. This matches the behavior of the **DripFeed** malware used by **HydroPhantom**.

**ATT&CK - ICS**:
- **T0830 - PLC Firmware Modification**: Tampering with device firmware for persistence.
- **T0822 - Information Repository Recovery**: Mirroring operational data for intelligence gathering.

## Inject 5: The Extortion Deadline (AquaLeak)

**Timestamp**: T+05:30

**Source**: Dark Web Monitoring / Email

**Content**: **AquaLeak** has posted a "teaser" of stolen customer billing data on their leak site. They have sent an ultimatum to the utility's general manager: Pay 50 BTC within 12 hours, or the full 20GB dataset will be released, and the "locked" administrative servers will be permanently wiped.

**ATT&CK - ICS**:
- **T0828 - Loss of Productivity and Revenue**: Financial extortion and data destruction threat.

## Inject 6: Subtle Process Drift (HydroPhantom)

**Timestamp**: T+07:00

**Source**: SCADA Historian / Operator Observation

**Content**: A senior operator notices that the pH levels in the post-treatment basin are drifting near the upper limit of the "Safe" range. The HMI shows the pumps are operating normally, but manual titration tests show a discrepancy. This suggests a **Manipulation of Control** where the HMI is being fed "spoofed" data while the physical process is being altered.

**ATT&CK - ICS**:
- **T0831 - Manipulation of Control**: Altering physical processes.
- **T0829 - Loss of View**: Spoofing HMI data to hide process changes.

## Inject 7: Shadow C2 Discovery (HydroPhantom)

**Timestamp**: T+09:00

**Source**: Network Forensic Team

**Content**: Incident responders identify an outbound encrypted tunnel originating from a maintenance workstation in the OT DMZ. The traffic is disguised as standard NTP (Network Time Protocol) updates but occurs at irregular intervals. This is identified as the C2 channel for **HydroPhantom's "DripFeed"** malware.

**ATT&CK - ICS**:
- **T0885 - Remote Services**: Use of remote access for C2.
- **T0869 - Standard Application Layer Protocol**: Tunneling C2 traffic through common protocols.

## Inject 8: The "Water Hammer" Logic Bomb (HydroPhantom)

**Timestamp**: T+11:00

**Source**: Malware Reverse Engineering

**Content**: Analysis of the modified PLC firmware (from Inject 4) reveals a "Logic Bomb." If the C2 connection is lost for more than 24 hours, the code is programmed to rapidly cycle the main distribution valves. This is intended to create a **Water Hammer** effect, potentially causing physical pipe damage.

**ATT&CK - ICS**:
- **T0814 - Denial of Service**: Potential for physical destruction of infrastructure.
- **T0807 - Command Generation**: Malicious logic generating damaging physical commands.

## Inject 9: Media and Public Panic (External)

**Timestamp**: T+13:00

**Source**: Social Media / Local News

**Content**: A video goes viral on social media showing the defaced HMI at the utility office. Local news is now reporting "unconfirmed reports of contaminated water," leading to a run on bottled water. The Mayor is demanding a public statement from the Utility Director within the hour.
**Impact**: Strategic communication and crisis management pressure.
