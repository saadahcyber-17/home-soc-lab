# 04 - New User Account Creation Detection

## Objective

The objective of this detection is to identify the creation of new user accounts on Windows systems that may indicate unauthorized persistence, privilege escalation, insider activity, or attacker post-compromise actions.

User account creation is a legitimate administrative activity; however, threat actors frequently create new accounts after gaining access to a system in order to maintain persistence, evade detection, and establish long-term access to the environment.

By monitoring Windows User Account Creation events, security analysts can detect potentially unauthorized account creation activity and investigate systems that may have been compromised.

---

## MITRE ATT&CK Mapping

| Field          | Value          |
| -------------- | -------------- |
| Technique ID   | T1136          |
| Technique Name | Create Account |
| Tactic         | Persistence    |
| Severity Level | High           |

---

## Data Source

| Field             | Value                               |
| ----------------- | ----------------------------------- |
| Log Source        | Windows Security Logs               |
| Log Provider      | Microsoft Windows Security Auditing |
| Event ID          | 4720                                |
| Event Description | A User Account Was Created          |

---

## Attack Simulation

### Scenario

To simulate unauthorized account creation activity, a new local user account was created on a Windows endpoint using administrative privileges.

### Steps Performed

1. Opened Command Prompt as Administrator.
2. Executed a command to create a new local user account.
3. Windows generated a User Account Creation event.
4. Windows recorded the activity as Event ID 4720 in the Security Event Log.
5. Splunk Universal Forwarder collected and forwarded the logs to Splunk Enterprise.
6. The events were analyzed to validate the detection logic.

### Commands Executed

```cmd
net user hacker123 Password@123 /add
```

---

## Detection Logic

This detection monitors Windows Security Event ID 4720, which indicates that a new user account has been created on the system.

Threat actors commonly create new accounts after obtaining administrative access in order to establish persistence and maintain long-term access to compromised systems.

The detection identifies newly created user accounts and provides visibility into account creation activity for further investigation.

### Detection Conditions

* Monitor Event ID 4720
* Identify newly created user accounts
* Record the account creator
* Record the newly created account name
* Track the source system where the account was created

### Detection Threshold

* Any User Account Creation Event (Event ID 4720)

### Security Objective

Identify unauthorized or suspicious account creation activity that may indicate persistence mechanisms, insider threats, or attacker post-compromise actions.

---

## SPL Query

```spl
index="main" EventCode=4720
| table _time ComputerName
```

### Query Breakdown

| Command        | Purpose                                             |
| -------------- | --------------------------------------------------- |
| EventCode=4720 | Filters User Account Creation events                |
| table          | Displays relevant fields for analysis               |

---

## False Positives

Legitimate account creation activity may generate alerts, including:

* IT administrators creating user accounts
* New employee onboarding
* Service account creation
* Test account creation in lab environments
* Automated provisioning systems

---

## Remediation

1. Verify whether the account creation was authorized.
2. Review the user who created the account.
3. Investigate the system where the account was created.
4. Validate the purpose of the newly created account.
5. Review recent authentication activity associated with the account.
6. Disable or remove unauthorized accounts.
7. Perform additional threat hunting for related persistence mechanisms.

---

