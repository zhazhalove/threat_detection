### Threat Severity

| Score | Threat Level                                                                                       | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | The threat is passive but could lead to further malicious activity.                                | - Unusual login attempts from foreign locations<br>- Detection of commonly used penetration testing tools in the network<br>- Unexpected email gathering activities<br>- Excessive DNS queries for uncommon domains<br>- Light, irregular traffic to unusual external IP addresses<br>- Observing public information gathering on company employees<br>- Increased activity on old, unused accounts<br>- Minor anomalies in system performance metrics<br>- Small-scale scanning from known benign sources<br>- Detection of encrypted files with unknown keys<br>- Alerts on low-reputation IP addresses accessing public resources<br>- Observations of test payloads in web application logs<br>- Unusual but approved software installation patterns<br>- Irregular patterns in outbound email traffic<br>- Unexpected access to public-facing APIs<br>- Slight irregularities in login times out of office hours<br>- Detection of outdated but not exploited vulnerabilities<br>- Minor deviations in network protocol usage<br>- Alerts on low-level system changes by unknown processes<br>- Use of alternative data storage or transmission methods                                                                                                                                                                                                              |
| 2     | The threat is actively in the environment but presents a low risk at this stage in the kill chain. | - Discovery of malware in a sandbox environment<br>- Successful phishing email delivery without engagement<br>- Detection of command and control traffic from a non-critical system<br>- Unauthorized access to non-sensitive data<br>- Presence of a known exploit kit in the network without execution<br>- Low-level user privilege escalation attempts<br>- Evidence of lateral movement in peripheral network segments<br>- Detection of suspicious but non-malicious email attachments<br>- Identification of abnormal script execution in non-critical systems<br>- Minor integrity anomalies in system files<br>- Alerts on unauthorized but unsuccessful login attempts<br>- Detection of known malware communication protocols with no data exfiltration<br>- Temporary disabling of security controls on secondary systems<br>- Observation of data staging in non-essential systems<br>- Unauthorized network scanning from an internal source<br>- Detection of encryption activity in non-critical data stores<br>- Use of stolen credentials on non-essential services<br>- Irregular file transfers within the network<br>- Unsuccessful attempts to bypass endpoint protection<br>- Evidence of spear-phishing campaigns targeting non-key personnel                                                                                                     |
| 3     | The threat presents a severe threat to the organization.                                           | - Execution of a zero-day exploit against critical infrastructure<br>- Successful exfiltration of sensitive customer data<br>- Detection of advanced persistent threat (APT) activity within core networks<br>- Compromise of high-level administrative credentials<br>- Widespread deployment of ransomware across essential systems<br>- Breach and data leak of proprietary or classified information<br>- Disruption of critical operational technology (OT) systems<br>- Unauthorized access and manipulation of financial systems<br>- Targeted attacks on supply chain partners with direct organizational impact<br>- Deep penetration and persistence within the network undetected over time<br>- Complete takeover of customer-facing platforms<br>- Systemic manipulation or corruption of data integrity<br>- High-volume DDoS attacks against critical online services<br>- Discovery of surveillance malware within sensitive communication systems<br>- Implementation of backdoors in critical network infrastructure<br>- Theft and public release of sensitive employee information<br>- Exploitation of vulnerabilities leading to physical damage<br>- Unauthorized control of critical medical devices<br>- Large-scale identity theft affecting customers or employees<br>- Extensive intellectual property theft with evidence of competitive use |

### Organizational Alignment

| Score | Description                                                                           | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ----- | ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | The threat is irrelevant to the organization.                                         | 1. A threat targeting macOS endpoints in a Windows-only environment.<br>2. Linux ransomware in a Windows-dominated environment.<br>3. Mobile-focused malware when the organization does not use mobile devices for operations.<br>4. An attack leveraging a vulnerability in software the organization does not use.<br>5. Threats specific to hardware the organization has phased out.<br>6. Sector-specific attacks irrelevant to the organization's industry.<br>7. Geographically focused attacks outside the organization's area of operation.<br>8. Attacks on technologies the organization has no plans to adopt.<br>9. Threat actors known to only target individuals, not corporations.<br>10. Specific social engineering scams irrelevant to the organization's communication channels.                                                                                                                                                                 |
| 1     | The threat is likely not going to target your organization but the risk still exists. | 1. A threat actor primarily focused on targeting a geography outside your own but known to target your industry.<br>2. Emerging malware trends not yet seen in your region but prevalent in others.<br>3. Threats targeting industries similar to yours but not directly related.<br>4. Cyber campaigns focused on larger entities while you operate a small to medium business.<br>5. Generic phishing campaigns not tailored to your sector.<br>6. Attacks leveraging vulnerabilities in less critical software your organization seldom uses.<br>7. Information-stealing malware primarily targeting consumer data when your organization deals with B2B.<br>8. Threat actors known for espionage in sectors adjacent to yours.<br>9. Ransomware gangs historically targeting public institutions, and your business is private.<br>10. Insider threat tactics mainly reported in industries with high employee churn, which does not apply to your organization. |
| 2     | The threat is widespread/untargeted.                                                  | 1. A mass Emotet malspam campaign.<br>2. Widespread phishing attempts not targeting any specific industry.<br>3. Generalized ransomware attacks seeking to exploit common vulnerabilities.<br>4. Broad DDoS attacks aimed at disrupting services indiscriminately.<br>5. Malvertising campaigns affecting a wide range of users.<br>6. Cryptojacking efforts exploiting widespread web platform vulnerabilities.<br>7. SQL injection attacks targeting websites regardless of their content or owner.<br>8. Credential stuffing attacks using previously breached databases.<br>9. Scareware campaigns aiming to dupe less tech-savvy users.<br>10. Watering hole attacks not specific to one sector or industry.                                                                                                                                                                                                                                                    |
| 3     | The threat specifically targets your organization.                                    | 1. Known threat based on internal observations or a threat actor known to target your geography and industry.<br>2. Spear-phishing emails tailored to your organization's employees.<br>3. Advanced persistent threat (APT) groups with a history of targeting your sector.<br>4. Ransomware customized to exploit your organization's specific network vulnerabilities.<br>5. Insider threats with knowledge of your organization's systems and data.<br>6. Social engineering attacks designed around your corporate culture.<br>7. Competitor-driven espionage targeting your intellectual property.<br>8. Supply chain attacks aimed at software or services your organization relies on.<br>9. Threats exploiting recently disclosed vulnerabilities before your organization can patch them.<br>10. Targeted DDoS attacks aiming to disrupt your specific online services.                                                                                     |

### Detection Coverage

| Score | Description                                                              | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | In-depth coverage is already provided for this specific technique.       | 1. Antivirus software detects malware based on signatures.<br>2. Firewall rules block known malicious IP addresses.<br>3. Intrusion detection systems (IDS) flag known exploit traffic.<br>4. Email filtering systems block phishing emails.<br>5. Web application firewalls (WAF) prevent SQL injection attacks.<br>6. Endpoint detection and response (EDR) tools identify and isolate ransomware.<br>7. Network segmentation prevents lateral movement.<br>8. Secure web gateways block access to malicious websites.<br>9. Data loss prevention (DLP) systems monitor and block sensitive data exfiltration.<br>10. Identity and access management (IAM) controls prevent unauthorized access.<br>11. Multi-factor authentication (MFA) thwarts credential stuffing attacks.<br>12. Security information and event management (SIEM) systems correlate threat indicators.<br>13. Application whitelisting allows only approved software to run.<br>14. Patch management systems keep software up to date.<br>15. Security awareness training reduces the risk of social engineering attacks.                                                                                       |
| 1     | This technique requires an update to the scope of an existing detection. | 1. Updating antivirus signatures to cover a new malware variant.<br>2. Adjusting firewall rules to block emerging threat IPs.<br>3. Tuning IDS to reduce false positives for exploit traffic.<br>4. Enhancing email filters to catch sophisticated phishing attempts.<br>5. Updating WAF rules to defend against new SQL injection techniques.<br>6. Refining EDR tool algorithms to better detect ransomware behavior.<br>7. Expanding network segmentation to additional critical assets.<br>8. Updating secure web gateway blacklists to include newly identified malicious sites.<br>9. Extending DLP monitoring to cover additional data types.<br>10. Adding new applications to the IAM policy.<br>11. Implementing additional factors in MFA to address new threats.<br>12. Updating SIEM correlation rules to include new indicators of compromise.<br>13. Adding recently released software to the application whitelist.<br>14. Accelerating patch deployment for critical vulnerabilities.<br>15. Refreshing security awareness training to address new phishing techniques.                                                                                               |
| 2     | No coverage for this requirement exists. A new detection is required.    | 1. Developing a detection mechanism for a zero-day exploit.<br>2. Creating new firewall rules for a previously unknown attack vector.<br>3. Implementing a new IDS signature for an emerging threat.<br>4. Designing a new email filtering rule to detect a novel phishing strategy.<br>5. Developing a new WAF rule set for an advanced web attack.<br>6. Creating a new EDR detection algorithm for a unique malware strain.<br>7. Establishing network segmentation for a newly identified critical asset.<br>8. Introducing a new category of websites to block in the secure web gateway.<br>9. Implementing a new DLP policy to protect against an emerging data exfiltration technique.<br>10. Adding coverage for a new application or system in IAM policies.<br>11. Introducing a new authentication method in response to a novel attack.<br>12. Creating new SIEM correlation rules for detecting previously unidentified activities.<br>13. Whitelisting a new, essential application not previously covered.<br>14. Developing a patch management strategy for a new piece of software.<br>15. Launching a new security awareness module on a recent cyber threat trend. |

### Active Exploits

The Active Exploits score should only be used in the scoring process if the detection requirement involves detecting a specific exploit.

First, identify whether the organization is vulnerable to the exploit based on which technologies and software versions are affected.<br><br>

_Table 1.1 – Active Exploit (Relevance) Scoring_
| Score | Description | Examples |
|-------|-------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0 | The organization is not vulnerable to the exploit. | 1. Exploit targets a different operating system.<br>2. The software version affected by the exploit is not used.<br>3. The organization uses a different technology stack.<br>4. Security measures already mitigate the exploit risk.<br>5. The exploit affects a service not exposed by the organization.<br>6. The infrastructure is hosted in a way that is not affected.<br>7. The organization uses cloud services that are not vulnerable.<br>8. The exploit targets hardware not used by the organization.<br>9. The affected software is used in a non-standard, secure configuration.<br>10. The organization has already applied a workaround.<br>11. The exploit is for a feature not enabled in the organization’s setup.<br>12. The organization’s network architecture prevents the exploit’s effectiveness.<br>13. The exploit requires access not available to external attackers.<br>14. The vulnerability was previously identified and mitigated.<br>15. The organization uses a proprietary system unaffected by the exploit. |
| 1 | The organization is vulnerable to the exploit but the turnaround time of a patch is quick. | 1. The vendor has announced a patch release date.<br>2. A temporary fix is available and can be quickly implemented.<br>3. The organization has a rapid patch deployment process.<br>4. The vulnerability is in a non-critical system with a patch coming.<br>5. The exploit affects software that is easily updated.<br>6. The organization has a subscription for automatic security updates.<br>7. The patch is already in the final stages of testing.<br>8. The organization can quickly apply vendor-supplied mitigations.<br>9. A third-party security solution can mitigate the risk shortly.<br>10. The IT team has prioritized the patch for immediate rollout.<br>11. The affected system can be temporarily isolated until the patch.<br>12. A patch management tool is in place to speed up the process.<br>13. The organization has a strong relationship with the vendor for quick fixes.<br>14. Pre-release access to patches allows for quick deployment.<br>15. The exploit is well-understood, and an in-house patch is ready. |
| 2 | The organization is vulnerable and a patch is unavailable or will not be deployed soon. | 1. The vendor has not acknowledged the vulnerability.<br>2. The affected software is no longer supported.<br>3. The organization’s patching cycle is slow due to bureaucracy.<br>4. The system cannot be updated without significant downtime.<br>5. Custom software is affected, and development resources are limited.<br>6. The patch conflicts with other critical software.<br>7. The organization lacks the expertise to develop a workaround.<br>8. The exploit affects a critical system with no immediate patch.<br>9. The organization’s security budget is insufficient for a quick fix.<br>10. The vulnerability is complex, and no fix is in sight.<br>11. The affected system is due for replacement, delaying the patch.<br>12. Compliance requirements prevent quick changes to the system.<br>13. The organization is waiting for a comprehensive security update.<br>14. The exploit requires a significant architectural change to mitigate.<br>15. The patch is available but incompatible with the organization’s setup. |

<br><br>This table focuses on how likely it is that the vulnerability will be exploited based on public reporting of the availability of exploit code and observed activity.<br><br>

_Table 1.2 – Active Exploit (Prevalence) Scoring_
| Score | Description | Examples |
|-------|-------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | No exploit code or in-the-wild activity has been observed. | 1. The vulnerability is newly discovered with no known exploits.<br>2. The threat is theoretical with no practical exploitation demonstrated.<br>3. Security researchers have disclosed the vulnerability responsibly.<br>4. The vulnerability is known but considered low risk with no active interest.<br>5. The exploit is highly complex, reducing the likelihood of immediate use.<br>6. The affected software is not widely used, limiting interest.<br>7. The exploit requires conditions not commonly found in the wild.<br>8. The vulnerability is in a beta version of software with limited release.<br>9. The organization monitors threat feeds with no mention of the exploit.<br>10. The exploit has been hinted at in forums but not confirmed.<br>11. The vulnerability requires insider access, reducing external threats.<br>12. The exploit is for a feature rarely enabled in real-world scenarios.<br>13. The vulnerability was disclosed with immediate mitigations available.<br>14. The organization has not observed any related security incidents.<br>15. The exploit’s complexity makes it unlikely to be weaponized soon. |
| 2 | Some in-the-wild activity has been observed but no public exploit code is available. | 1. Limited attacks targeting specific industries have been reported.<br>2. Security organizations have issued warnings based on suspicious activities.<br>3. The exploit has been used in targeted phishing campaigns.<br>4. Incident response teams have encountered the exploit in isolated cases.<br>5. Anecdotal evidence suggests the exploit's use in espionage.<br>6. The vulnerability has been exploited in a proof-of-concept attack.<br>7. Rumors of exploit use have circulated among cybersecurity forums.<br>8. The exploit is known to a select group of advanced threat actors.<br>9. Indicators of compromise related to the exploit have been detected.<br>10. The organization has received targeted threat intelligence warnings.<br>11. The exploit has been used in a narrowly focused malware campaign.<br>12. Cybersecurity vendors have reported unusual activity suggesting exploitation.<br>13. The exploit has been implicated in non-publicized security breaches.<br>14. The exploit is suspected in incidents affecting peer organizations.<br>15. The organization has seen attempts that hint at the exploit’s use. |
| 3 | Exploit code is publicly available and actively being used by threat actors. | 1. The exploit code has been posted on public forums.<br>2. The exploit is included in popular penetration testing tools.<br>3. The vulnerability is being exploited in widespread phishing attacks.<br>4. The exploit has been used in a high-profile data breach.<br>5. Cybersecurity agencies have issued alerts about active exploitation.<br>6. The exploit is part of a well-known malware’s toolkit.<br>7. The exploit has been sold on dark web marketplaces.<br>8. Automated scanning for the vulnerability has spiked.<br>9. The exploit is leveraged in ransomware campaigns.<br>10. The organization has detected the exploit in network traffic.<br>11. The exploit is discussed in threat actor communications intercepted.<br>12. The vulnerability is exploited in attacks against critical infrastructure.<br>13. The exploit is used in attacks attributed to nation-state actors.<br>14. Security products have been updated to detect the exploit specifically.<br>15. The organization has responded to incidents directly involving the exploit. |
