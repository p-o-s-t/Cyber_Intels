# Threat Actor Profile: XENOTIME (Real-World)

## Summary
**XENOTIME** is widely considered one of the most dangerous threat actors due to its deliberate targeting of **Safety Instrumented Systems (SIS)**. They are responsible for the **TRISIS** (also known as TRITON) malware, which targeted Schneider Electric's Triconex safety systems.

## Capability
- **Sophistication**: High
- **Tools**: **TRISIS** (SIS-specific malware), custom credential harvesting tools, and living-off-the-land techniques (PSExec, standard Windows commands).
- **Specialization**: Deep knowledge of safety system logic and industrial safety protocols.

## Intent
Intentional disruption of industrial safety systems, which can lead to catastrophic physical damage, environmental impact, or loss of life.

## Opportunities
Targeting Oil & Gas and Electric Utilities, often pivoting from compromised vendor or manufacturer networks into asset owner environments.

## ICS Impact (MITRE ATT&CK for ICS)
- **TA0106 - Inhibit Response Function**: Specifically targeting SIS to prevent safe shutdowns.
- **T0880 - Stop Control Process**: Causing industrial systems to shut down or operate in an unsafe state.
- **T0829 - Loss of View**: Obscuring the operational status of safety systems during an attack.
