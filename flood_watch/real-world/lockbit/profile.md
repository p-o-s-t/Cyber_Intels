# Threat Actor Profile: LockBit (Real-World)

## Summary
**LockBit** is one of the most prolific Ransomware-as-a-Service (RaaS) operations. Since its emergence in 2019, it has undergone several iterations, most notably **LockBit 3.0** (LockBit Black). The group targets a wide array of sectors, including critical infrastructure and water utilities.

## Capability
- **Sophistication**: High (RaaS model)
- **Techniques**: Exploiting public-facing vulnerabilities (e.g., CitrixBleed, Fortinet), RDP/VPN brute-forcing, and credential stuffing.
- **Tools**: LockBit 3.0 builder, **StealBit** (custom exfiltration tool), Cobalt Strike, and Mimikatz.

## Intent
Financial gain through "Double Extortion" (data encryption and threat of leaking sensitive information).

## Opportunities
Targeting organizations with unpatched edge devices or weak multi-factor authentication (MFA) on remote access portals.

## Notable Incidents (Water/WWS)
- **Aguas do Porto (2023)**: Targeted the municipal water company of Porto, Portugal. While the water supply remained safe, the attack disrupted administrative and customer service systems, and sensitive data was threatened for release.

## TTPs (MITRE ATT&CK for ICS)
- **TA0108 - Internet Accessible Device**: Exploiting vulnerabilities in VPNs and firewalls.
- **T0859 - Valid Accounts**: Use of stolen credentials for initial access and lateral movement.
- **T0828 - Loss of Productivity and Revenue**: Encrypting business and operational support systems.
