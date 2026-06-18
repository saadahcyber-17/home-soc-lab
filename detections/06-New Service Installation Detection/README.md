# 06 - New Service Installation Detection

## Objective

The objective of this detection is to identify newly installed Windows services that may indicate unauthorized persistence, privilege escalation, malware installation, or attacker post-compromise activity.

Windows Services are legitimate components used to run applications and system processes in the background. However, threat actors frequently abuse services to maintain persistence, execute malicious payloads, evade detection, and regain access to compromised systems after a reboot.

By monitoring Windows Service Installation events, security analysts can detect potentially unauthorized service creation activity and investigate systems that may have been compromised.

---

## MITRE ATT&CK Mapping

| Field          | Value                                            |
| -------------- | ------------------------------------------------ |
| Technique ID   | T1543.003                                        |
| Technique Name | Create or Modify System Process: Windows Service |
| Tactic         | Persistence, Privilege Escalation                |
| Severity Level | High                                             |

---

## Data Source

| Field             | Value                                 |
| ----------------- | ------------------------------------- |
| Log Source        | Windows System Logs                   |
| Log Provider      | Service Control Manager               |
| Event ID          | 7045                                  |
| Event Description | A Service Was Installed in the System |

---

## Attack Simulation

### Scenario

To simulate persistence activity, a new Windows service was created using administrative privileges on a Windows endpoint.

### Steps Performed

1. Opened Command Prompt as Administrator.
2. Executed a command to create a new Windows service.
3. Windows registered the service with the Service Control Manager.
4. Windows generated a Service Installation event.
5. Windows recorded the activity as Event ID 7045 in the System Event Log.
6. Splunk Universal Forwarder collected and forwarded the logs to Splunk Enterprise.
7. The events were analyzed to validate the detection logic.

### Commands Executed

```cmd
sc create TestService binPath= "C:\Windows\System32\cmd.exe"
```

### Verification Commands

```cmd
sc query TestService
```

---

## Detection Logic

This detection monitors Windows System Event ID 7045, which indicates that a new service has been installed on the system.

Threat actors frequently create malicious services after obtaining administrative access in order to establish persistence, execute malware, and maintain long-term access to compromised systems.

The detection identifies newly installed services and provides visibility into service creation activity for further investigation.

### Detection Conditions

* Monitor Event ID 7045
* Identify newly installed services
* Record the service name
* Record the executable path associated with the service
* Track the source system where the service was installed

### Detection Threshold

* Any Service Installation Event (Event ID 7045)

### Security Objective

Identify unauthorized service installations that may indicate persistence mechanisms, malware deployment, or attacker post-compromise activity.

---

## SPL Query

```spl
index="main" EventCode=7045
| table _time ComputerName
```

### Query Breakdown

| Command        | Purpose                               |
| -------------- | ------------------------------------- |
| EventCode=7045 | Filters service installation events   |
| table          | Displays relevant fields for analysis |

---

## False Positives

Legitimate service installations may generate alerts, including:

* Software installations and updates
* Antivirus or endpoint security deployments
* System administration activities
* Enterprise software management tools
* Application upgrades and maintenance operations

---

## Remediation

1. Verify whether the service installation was authorized.
2. Review the service name and executable path.
3. Investigate the account responsible for the installation.
4. Validate the legitimacy of the installed service.
5. Check whether the service automatically starts at system boot.
6. Disable and remove unauthorized services.
7. Scan the associated executable for malicious activity.
8. Perform additional threat hunting for related persistence mechanisms.

---

