# 05 - User Added to Administrators Group Detection

## Objective

The objective of this detection is to identify user accounts that have been added to the local Administrators group on Windows systems.

Adding a user to the Administrators group significantly increases the privileges available to that account and may indicate unauthorized privilege escalation, persistence, insider activity, or attacker post-compromise actions.

Threat actors frequently add compromised or newly created accounts to privileged groups in order to gain administrative control over a system and maintain long-term access.

By monitoring privileged group membership changes, security analysts can detect potentially unauthorized privilege escalation activity and investigate systems that may have been compromised.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---------|---------|
| Technique ID | T1098 |
| Technique Name | Account Manipulation |
| Tactic | Privilege Escalation, Persistence |
| Severity Level | High |

---

## Data Source

| Field | Value |
|---------|---------|
| Log Source | Windows Security Logs |
| Log Provider | Microsoft Windows Security Auditing |
| Event ID | 4732 |
| Event Description | A Member Was Added to a Security-Enabled Local Group |

---

## Attack Simulation

### Scenario

To simulate privilege escalation activity, an existing local user account was added to the local Administrators group using administrative privileges.

### Steps Performed

1. Opened Command Prompt as Administrator.
2. Created a test user account (if not already present).
3. Added the user account to the local Administrators group.
4. Windows generated a local group membership modification event.
5. Windows recorded the activity as Event ID 4732 in the Security Event Log.
6. Splunk Universal Forwarder collected and forwarded the logs to Splunk Enterprise.
7. The events were analyzed to validate the detection logic.

### Commands Executed

```cmd
net localgroup administrators hacker123 /add
```

---

## Detection Logic

This detection monitors Windows Security Event ID 4732, which indicates that a user account has been added to a security-enabled local group.

Attackers frequently add compromised accounts to privileged groups after obtaining access to a system. This allows them to perform administrative actions, disable security controls, establish persistence, and maintain long-term access.

The detection identifies accounts added to privileged groups and provides visibility into privilege escalation activity for further investigation.

### Detection Conditions

* Monitor Event ID 4732
* Identify accounts added to local security groups
* Record the account that performed the action
* Record the account added to the group
* Record the target group name
* Track the source system where the modification occurred

### Detection Threshold

* Any Group Membership Modification Event (Event ID 4732)

### Security Objective

Identify unauthorized privilege escalation and persistence activities through modifications to privileged group memberships.

---

## SPL Query

```spl
index="main" EventCode=4732
| table _time
```

### Query Breakdown

| Command | Purpose |
|----------|----------|
| EventCode=4732 | Filters group membership modification events |
| table | Displays relevant fields for analysis |

---

## False Positives

Legitimate group membership modifications may generate alerts, including:

* IT administrators granting administrative access
* User privilege changes during onboarding
* Helpdesk account administration activities
* System maintenance operations
* Lab and testing environment configurations

---

## Remediation

1. Verify whether the group membership change was authorized.
2. Review the user account that performed the action.
3. Investigate the account added to the privileged group.
4. Validate the business justification for the privilege assignment.
5. Review recent authentication and account activity.
6. Remove unauthorized accounts from privileged groups.
7. Reset credentials if account compromise is suspected.
8. Perform additional threat hunting for related privilege escalation activity.

---
