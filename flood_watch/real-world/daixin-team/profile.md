# Threat Actor Profile: Daixin Team (Real-World)

## Summary
**Daixin Team** is a cybercrime group that has been active since at least June 2022. They primarily target the healthcare sector and critical infrastructure, specializing in data exfiltration and ransomware deployment.

## Capability
- **Sophistication**: Medium
- **Techniques**: Gaining initial access via vulnerable VPN servers or stolen VPN credentials. They often use Rclone for data exfiltration to cloud storage.
- **Tools**: Ransomware based on leaked BabbelLocker source code, Rclone, and Ngrok for tunneling.

## Intent
Financial gain through ransomware and data extortion.

## Opportunities
Exploiting legacy VPN infrastructure and lack of segmentation between IT and OT management networks.

## Notable Incidents (Water/WWS)
- **North Texas Municipal Water District (2023)**: The group claimed responsibility for an attack that disrupted the district's internal business network and phone systems. Over 33,000 files containing customer and employee data were reportedly stolen.

## TTPs (MITRE ATT&CK for ICS)
- **TA0109 - External Identity and Access Management**: Exploiting weak VPN authentication.
- **TA0103 - Lateral Movement**: Pivoting through the network using RDP and SSH.
- **T0822 - Information Repository Recovery**: Exfiltrating sensitive customer and operational data for extortion.
