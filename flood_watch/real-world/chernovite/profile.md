# Threat Actor Profile: CHERNOVITE (Real-World)

## Summary
**CHERNOVITE** is a highly sophisticated threat group responsible for the development of **PIPEDREAM**, a modular ICS-specific malware framework. PIPEDREAM is the seventh known ICS-specific malware and is designed to disrupt, degrade, and potentially destroy industrial environments.

## Capability
- **Sophistication**: Very High
- **Framework**: **PIPEDREAM**, which can scan for devices, brute-force passwords, sever connections, and crash target devices.
- **Protocols**: Expert use of ICS-specific protocols including FINS, Modbus, CoDeSys, and OPC-UA.

## Intent
Strategic disruption or destruction of critical infrastructure, particularly in the LNG and electric power sectors.

## Opportunities
Targets equipment from major manufacturers such as Schneider Electric, Omron, and any system utilizing CoDeSys-based PLCs or OPC UA.

## ICS Impact (MITRE ATT&CK for ICS)
- **TA0105 - Impair Process Control**: Manipulation of control and Loss of Control.
- **TA0106 - Inhibit Response Function**: Disruption of safety systems and emergency stops.
- **T0830 - PLC Firmware Modification**: Capability to install or modify PLC logic and firmware.
