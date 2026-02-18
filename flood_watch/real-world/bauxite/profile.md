# Threat Actor Profile: BAUXITE (Real-World)

## Summary
**BAUXITE** is a threat group with substantial technical overlaps with the pro-Iranian hacktivist persona **CyberAv3ngers**. They are capable of Stage 2 ICS Cyber Kill Chain operations, demonstrating the ability to compromise PLCs and deploy custom backdoors on OT devices.

## Capability
- **Sophistication**: Medium
- **Techniques**: Exploiting publicly known vulnerabilities, monitoring OEM security advisories, and using Kali Linux-based tools.
- **Tools**: Linux backdoors with C2 over MQTT.

## Intent
Ideological disruption and geopolitical signaling, often aligned with Iranian interests.

## Opportunities
Active monitoring of OT/ICS OEM advisories to identify and exploit unpatched vulnerabilities in industrial equipment.

## ICS Impact (MITRE ATT&CK for ICS)
- **TA0105 - Impair Process Control**: Denial of Control, Loss of Control, and Loss of Availability.
- **TA0107 - Denial of View**: Disruption of monitoring capabilities.
- **T0828 - Loss of Productivity and Revenue**: Impacting business operations via OT disruption.
