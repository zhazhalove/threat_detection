# Submitting Detection Requirements to the Detection Engineering Team

## Purpose

This document outlines the process and required information for submitting detection requirements to the Detection Engineering (DE) team. Providing clear, detailed, and well-supported requirements helps us prioritize effectively and develop robust detections to improve our organization's security posture.

## Submission Process

1.  **Identify the Need:** A detection need can arise from various sources, including Threat Intelligence (internal or external), SOC/IR findings, Red Team exercises, Business/Compliance needs, standard IT Operations, or ongoing analysis (Validation, Metrics, Monitoring). See the examples section below for illustrations.
2.  **Gather Information:** Collect all relevant details as outlined in the template below. Focus on providing context, scope, known exceptions, and supporting evidence.
3.  **Submit via [Ticketing System Name - NAME]:** All requirements *must* be submitted via a ticket in [NAME]. Use the "Detection Requirement" issue type/template if available, or copy and paste the template below into the ticket.
4.  **Triage & Development:** The DE team will review the submitted ticket, triage it based on priority criteria (see [Link to Triage Process Wiki Page] if applicable), and assign it for investigation and development. You can track the progress via the ticket.

---

## Detection Requirement Submission Template

Use the following template when creating your detection requirement ticket. Fill in all sections as completely as possible.

### 1. Requesting Organization / Individual

* **Team/Department:** *[e.g., SOC L1, Incident Response, Threat Intel, Red Team, Compliance, IT Operations, Network Engineering]*
* **Requestor Name:** *[Your Full Name]*
* **Contact Email:** *[Your Email Address]*
* **Date Submitted:** *[YYYY-MM-DD]*

### 2. Description of Detection Need

* **What behavior, tool, technique, or indicator should be detected?**
    *(Provide a concise summary. Be as specific as possible. Include MITRE ATT&CK IDs if known, e.g., T1053.005 - Scheduled Task/Job: Scheduled Task)*
    > *[ **Enter detailed description here.** Example: "Detect the creation of scheduled tasks using schtasks.exe with command-line arguments commonly associated with persistence or lateral movement (e.g., /RU SYSTEM, network paths in /TR)." ]*

### 3. Reason / Justification

* **Why is this detection needed? What is the source or trigger for this request?**
    *(e.g., Observed during recent incident [Ticket #XXX], Finding from Red Team report [Link/Section], Threat Intel on Actor XYZ [Report Link], Need identified during threat hunt, Compliance Requirement [Policy Z], Tuning existing noisy rule [Rule ID: ABC], Legitimate IT activity causing noise, Need visibility into specific admin action)*
    > *[ **Explain the justification here.** Example: "Observed threat actor using schtasks.exe for persistence in Incident #12345. Current detections did not fire." ]*

### 4. Scope

* **Where should this detection apply? On which assets, networks, user groups, or platforms?**
    *(Be specific. e.g., "All Windows Servers", "Domain Controllers only", "All endpoints excluding the developers OU", "Production Linux environment", "Only traffic originating from external IPs")*
    > *[ **Define the scope here.** Example: "Apply to all Windows workstations and servers in the Corporate AD domain." ]*

### 5. Exceptions / Known False Positives

* **Under what specific, legitimate conditions should this detection *NOT* trigger an alert?**
    *(List known-good scenarios, authorized tools/scripts performing similar actions, specific user accounts/groups, processes/paths to exclude, etc. **This is critical for requests originating from IT Ops.**)*
    * [ **List Exception 1 here.** Example: "Legitimate scheduled tasks created by the SCCM deployment system (process: `CcmExec.exe`)." ]
    * [ **List Exception 2 here.** Example: "Tasks created by Backup Administrators group for approved backup jobs." ]
    * *(Add more bullet points as needed)*

### 6. Evidence / Supporting Information

* **Provide links, attachments, log snippets, IOCs, or references.**
    *(Crucial for investigation and testing! e.g., Links to OSINT/blog posts, specific IOCs (hashes, IPs, domains), malware sample reference (if available safely), relevant log excerpts (use code blocks), PCAP file locations/summaries, screenshots of legitimate activity causing alerts)*
    * [ **Link/Reference 1:** Example: `https://threatintel.example.com/report/actor-xyz-ttp` ]
    * **Log Snippet/IOC List:**
        ```text
        # Example Log Snippet
        Jan 01 10:00:00 HOSTNAME Security: EventID=4698, User=SYSTEM, TaskName=\evilTask, Command=C:\Windows\Temp\payload.exe
        # Example IOCs
        payload.exe SHA256: <hash>
        ```
    * *(Add more bullet points or code blocks as needed)*

---

**Thank you for your submission! The Detection Engineering team will review and triage this request based on priority and feasibility.**

---

## Examples of Requirement Sources and Resulting Submissions

The following examples illustrate how different situations lead to detection requirements. Consider how the details from these scenarios would populate the fields in the template above.

### Threat Intelligence (Open Source or Internal Feed)

* **Specific Blog Post Analysis:** Reading Trend Micro's research on Earth Kitsune/WhiskerSpy.
    * *Leads to requirements like:* Detect specific files (`popup.js`, `Codec-AVC1.msi`), PowerShell patterns, or C2 IoCs identified in the report.
* **Specific OSINT Feed/Pulse Processing:** Ingesting an AlienVault OTX pulse on an IcedID campaign.
    * *Leads to requirements like:* Detect specific campaign SHA256 hashes, domains (`wwwanydesk[.]top`), or IP addresses (`45.8.229[.]109`) from the pulse.
* **Specific Sandbox Report Review:** Analyzing a Qakbot sample (`08e2bf60...`) on VirusTotal shows specific commands (`arp -a`, `net view`) run via `wermgr.exe`.
    * *Leads to requirements like:* Detect execution of `arp -a`, `net view`, etc., when the parent process is `wermgr.exe`.
* **Malware Family TTP Report (e.g., CISA Advisory):** A CISA advisory details TTPs for 'LockBit 3.0' ransomware, including specific PowerShell commands for disabling security tools (T1562.001) and specific registry keys for persistence (T1547.001).
    * *Leads to requirements like:* Detect the specific PowerShell commands from the advisory executed with admin privileges. Detect modifications to the specific registry keys listed.
* **Indicator Relationship Analysis (e.g., VirusTotal):** Investigating a known malicious domain (`evil-c2[.]com`) on VirusTotal reveals consistent communication with a specific ASN (e.g., AS12345 known for bulletproof hosting) and dropping files matching `update_v[0-9].exe`.
    * *Leads to requirements like:* Detect network traffic to AS12345. Detect file creation events matching the `update_v[0-9].exe` pattern.

### Business Security Requirements / Compliance

* **Specific Unauthorized Software Policy:** Policy forbids XMRig crypto-mining.
    * *Leads to requirements like:* Detect `xmrig.exe` process or associated Stratum protocol traffic.
* **Specific Privileged Tool Restriction Policy:** `PsExec.exe` restricted to Domain Admins on specific servers.
    * *Leads to requirements like:* Detect PsExec use by non-Domain Admins or targeting non-approved systems.
* **Data Handling Policy:** Policy prohibits storing sensitive PII data on local endpoint drives; it must be on designated network shares.
    * *Leads to requirements like:* Detect files tagged as 'PII' (via DLP or EDR file tagging) being written outside approved network paths (e.g., `\\fileserv\CustomerData\`).
* **Cloud Security Policy:** Company policy mandates that all AWS S3 buckets must have server access logging enabled.
    * *Leads to requirements like:* Implement a detection (likely via cloud security posture management tool or scheduled script) that identifies S3 buckets missing the `loggingEnabled` configuration attribute.

### IT Operations / System Administration

* **Legitimate Activity Causing Noise:** SCCM patching via PowerShell triggers "Suspicious PowerShell Download Activity" rule (PoshDL101).
    * *Leads to requirements like:* Tune rule PoshDL101 to exclude downloads initiated by `CcmExec.exe` or from internal SCCM server IPs. *Provide SCCM process/server details in Exceptions/Evidence.*
* **Need for Visibility into Admin Actions:** PowerShell Remoting (`Enter-PSSession`) used daily by admins needs differentiation from malicious remote PowerShell.
    * *Leads to requirements like:* Detect remote PowerShell (WinRM logs, Event 4103/4104) *except* sessions from designated admin workstations targeting approved servers. *List authorized sources/targets in Exceptions/Scope.*
* **Anomalous Service Account Behavior:** `SVC_Backup` account attempts interactive logon (Logon Type 2) to a DC.
    * *Leads to requirements like:* Detect service accounts attempting interactive logons or logging in from unexpected source systems. *Identify normal behavior/systems in Exceptions.*
* **Proactive Whitelisting for New Tool:** Desktop Support deploying "RemoteSupportTool Pro".
    * *Leads to requirements like:* Analyze the tool's signatures (process names, hashes, network traffic) and update generic remote access detections to exclude it for authorized staff. *Provide tool documentation/installers in Evidence.*
* **Monitoring Log Flow:** Critical application server stopped sending logs to SIEM unnoticed.
    * *Leads to requirements like:* Implement a "Log Source Silent" detection alerting if logs from critical sources (by hostname, IP, log type) are missing for > 1 hour.

### Red Team Exercises

* **Specific Unseen Technique (Cred Access):** Red Team successfully used DCSync (T1003.006) without detection.
    * *Leads to requirements like:* Develop detections for DCSync network traffic or specific Event IDs related to replication requests from non-DCs.
* **Specific Unseen Technique (Defense Evasion):** Red Team used DLL side-loading (T1574.002) with `legit.exe` loading `evil.dll`.
    * *Leads to requirements like:* Detect `legit.exe` loading DLLs from non-standard paths, or detect creation of `evil.dll` in directories with `legit.exe`. *Provide executables/DLLs used in Evidence.*

### SOC Requests / Internal Findings

* **Specific Incident Post-Mortem:** Qakbot used ISO mounting from ZIP in Temp (T1553.005) in Black Basta incident #XYZ.
    * *Leads to requirements like:* Detect VHDMP Event ID 25 where path includes `\AppData\Local\Temp\` and `.zip\`. *Link to incident report in Evidence.*
* **Specific Alert Tuning Need:** "LSASS Memory Dump Creation" rule (LsassDump123) is noisy due to vulnerability scanner (`vulnscan.exe`).
    * *Leads to requirements like:* Tune rule LsassDump123 to exclude alerts generated by `vulnscan.exe`. *Provide examples of FP alerts in Evidence.*
* **Observed Alert Pattern:** SOC L1 notes Alert A (User Added to Privileged Group) often precedes Alert B (Suspicious Remote Login from New Geo) for the same user within minutes.
    * *Leads to requirements like:* Create a *correlation rule* flagging the sequence of Alert A then Alert B for the same user within ~5 minutes, raising severity.

### Continuous Activities (Validation, Metrics, Monitoring)

* **Specific Technique Gap (Validation):** Atomic Red Team test for Registry Run Key persistence (T1547.001) succeeded with no alert.
    * *Leads to requirements like:* Create detection for modifications to `HKCU\...\Run` and `HKLM\...\Run` registry keys.
* **Monitoring Noise:** New TOR exit node detection rule generates thousands of alerts daily due to vulnerability scanners.
    * *Leads to requirements like:* Tune the TOR detection rule to exclude traffic originating from scanner IPs. *List scanner IPs in Exceptions.*
* **Metrics Indicate Ineffectiveness:** SIEM metrics show rule "Potential Brute Force Login" (BF100) hasn't fired in 6 months despite known attempts.
    * *Leads to requirements like:* Investigate Rule BF100 for misconfiguration, incorrect logic, broken log source dependency, or scope issues.

---

## Questions?

If you have questions about submitting a detection requirement or need assistance gathering information, please contact the Detection Engineering team.