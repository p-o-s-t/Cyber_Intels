# Threat Actor Profile: Volt Typhoon (Real-World)

## Summary
**Volt Typhoon** is a state-sponsored threat group based in the People's Republic of China (PRC) that focuses on cyber espionage and maintaining persistent access to critical infrastructure organizations.

## Capability
- **Sophistication**: High
- **Techniques**: Living-off-the-land (LotL), exploitation of edge devices (SOHO routers, firewalls), use of valid credentials.
- **Targeting**: Water, energy, communications, and transportation sectors.

## Intent
Prepositioning for potential disruption of critical infrastructure during future regional crises.

## Opportunities
Exploiting end-of-life or unpatched network hardware to establish footholds in target networks.

## TTPs (MITRE ATT&CK for ICS)
- **TA0108 - Internet Accessible Device**: Targeting networking equipment.
- **T0822 - Information Repository Recovery**: Gathering operational data.
- **T0866 - Remote System Discovery**: Mapping the OT network from compromised IT environments.
