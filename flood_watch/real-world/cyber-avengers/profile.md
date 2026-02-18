# Threat Actor Profile: Cyber Avengers (Real-World)

## Summary
**Cyber Avengers** (CyberAv3ngers) is a hacktivist group affiliated with the Iranian Government Islamic Revolutionary Guard Corps (IRGC). They gained notoriety for targeting Unitronics PLCs in water utilities.

## Capability
- **Sophistication**: Low to Medium
- **Techniques**: Exploiting default credentials, defacement, simple ladder logic modification.
- **Targeting**: Water and wastewater systems, energy, and food/beverage sectors.

## Intent
Ideological and geopolitical pressure, specifically targeting equipment "made in Israel."

## Opportunities
Mass-scanning for internet-accessible PLCs (Port 20256) with default passwords (e.g., '1111').

## TTPs (MITRE ATT&CK for ICS)
- **TA0109 - External Identity and Access Management**: Use of default credentials (T0812).
- **TA0105 - Impair Process Control**: Defacement of HMIs (T0829) and disabling of remote access.
- **TA0107 - Denial of View**: Replacing graphical interfaces with splash pages.
