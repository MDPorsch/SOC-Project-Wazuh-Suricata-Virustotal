SOC Integrated Stack: Wazuh, Suricata, & VirusTotal
Technical Deployment & Proof of Concept


Project Overview
This project demonstrates the deployment of a professional-grade Security Operations Centre (SOC) stack. The architecture integrates host-based detection (Wazuh), network-based intrusion detection (Suricata), and automated threat intelligence (VirusTotal API).


System Architecture
The environment consists of a Wazuh Manager (Kali Linux) acting as the central brain, receiving telemetry from a Wazuh Agent, a Suricata IDS engine and VirusTotal as a malware detection service.

    IDS Layer: Suricata monitors eth0 for malicious signatures.
    SIEM Layer: Wazuh Manager aggregates logs and correlates events.
    Intelligence Layer: VirusTotal provides real-time hash analysis for file integrity monitoring (FIM).


Configuration Inventory

1. Suricata Network Flagging
To monitor specific threat actors, I implemented custom rules in /var/lib/suricata/rules/local.rules:

bash
alert ip [TARGET_IP] any -> any any (msg:"SECURITY_FLAG: Potential Threat IP Detected"; sid:1000002; rev:1;)
Use code with caution.


2. Wazuh-Suricata Integration
Integrated the engines by configuring the Wazuh Agent's ossec.conf to ingest Suricata’s EVE JSON output:

xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
Use code with caution.


3. VirusTotal Automated Response
Enabled automated threat lookups in the Wazuh Manager ossec.conf:

<integration>
  <name>virustotal</name>
  <api_key>[API_KEY_REDACTED]</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
Use code with caution.


Validation & Testing
To prove the system's efficacy, I conducted the following tests:
Test Case

  
IP Flagging	Pinging/Connecting from [Target IP]	Suricata triggers alert; Wazuh displays Level 12 Event.	✅ PASS
Malware Detection	Downloaded EICAR test file via wget	Wazuh FIM detects file; VirusTotal returns 70+ detections.	✅ PASS
Rule Integrity	wazuh-analysisd -t	Confirm zero XML syntax errors in local_rules.xml.	✅ PASS


Troubleshooting Log (Challenges Overcome)

    XML Syntax Errors: Encountered Element not closed errors during custom rule creation. Resolved by auditing local_rules.xml and ensuring proper spacing between XML attributes (rule id vs ruleid).
    
    Network Migration: Managed a full IP address change for the Manager. Successfully re-pointed the Wazuh Agent by updating the <address> tag in the agent configuration and restarting the service. 
    
    DEB aarch64 Errors:	Identified architecture mismatch; sourced correct arm64 packages for the CPU.	
    
    Permission Denied:	Used chmod +x and sudo to fix binary execution and directory access.



Daily Operations Commands

    Validate Config: sudo /var/ossec/bin/wazuh-analysisd -t
    Reload IDS Rules: sudo suricatasc -c reload-rules
    Monitor Intelligence Hits: grep "virustotal" /var/ossec/logs/ossec.log

Author: MOHAMMED ORUNSOLU

Date: February 2026

Role: Junior Security Engineer / SOC Analyst
