# 03 - PowerShell Execution Detection

## Objective

The objective of this detection is to identify PowerShell execution activity on Windows systems that may indicate malicious script execution, unauthorized administrative actions, or attacker post-exploitation activity.

PowerShell is a legitimate administrative tool commonly used by system administrators. However, threat actors frequently abuse PowerShell to execute malicious commands, download payloads, perform reconnaissance, establish persistence, and evade traditional security controls.

By monitoring PowerShell execution events, security analysts can detect potentially suspicious activity and investigate systems that may have been compromised.

---

## MITRE ATT&CK Mapping

| Field          | Value      |
| -------------- | ---------- |
| Technique ID   | T1059.001  |
| Technique Name | PowerShell |
| Tactic         | Execution  |
| Severity Level | Medium     |

---

## Data Source

| Field             | Value                           |
| ----------------- | ------------------------------- |
| Log Source        | Windows PowerShell Logs         |
| Log Provider      | Microsoft-Windows-PowerShell    |
| Event ID          | 4104                            |
| Event Description | PowerShell Script Block Logging |

---

## Attack Simulation

### Scenario

To simulate PowerShell execution activity, PowerShell was launched on a Windows endpoint and several commands were executed to generate PowerShell logging events.

### Steps Performed

1. Opened Windows PowerShell as a standard user.
2. Executed multiple PowerShell commands.
3. Generated PowerShell Script Block Logging events.
4. Windows recorded the activity as Event ID 4104.
5. Splunk Universal Forwarder collected and forwarded the logs to Splunk Enterprise.
6. The events were analyzed to validate the detection logic.

### Commands Executed

```powershell
Get-Process
Get-Service
Get-LocalUser
whoami
ipconfig
```

---

## Detection Logic

This detection monitors PowerShell Script Block Logging events (Event ID 4104).

PowerShell execution activity is commonly observed during administrative operations; however, it is also heavily used by attackers during the execution phase of an intrusion.

The detection identifies systems and users executing PowerShell commands and provides visibility into command execution activity for further investigation.

### Detection Conditions

* Monitor Event ID 4104
* Identify PowerShell script execution activity
* Record executed commands
* Track the user account responsible for execution
* Generate visibility into PowerShell usage

### Detection Threshold

* Any PowerShell execution event (Event ID 4104)

### Security Objective

Identify PowerShell execution activity that may indicate malicious command execution, attacker activity, or unauthorized administrative actions.

---

## SPL Query

```spl
index="main" EventCode=4104
| table _time ComputerName UserID Message
| sort - _time
```

### Query Breakdown

| Command        | Purpose                                           |
| -------------- | ------------------------------------------------- |
| EventCode=4104 | Filters PowerShell Script Block Logging events    |
| table          | Displays relevant fields for analysis             |
| sort - _time   | Shows the most recent PowerShell executions first |

---

## False Positives

Legitimate PowerShell activity may generate alerts, including:

* System administration tasks
* Software installation scripts
* IT automation activities
* Scheduled maintenance scripts
* Endpoint management tools

---

## Remediation

1. Review the executed PowerShell command.
2. Verify whether the command was authorized.
3. Identify the user account responsible for execution.
4. Investigate the source system where the command originated.
5. Determine whether the command exhibits malicious behavior.
6. Isolate the endpoint if malicious activity is confirmed.
7. Perform additional threat hunting for related activity.

---


