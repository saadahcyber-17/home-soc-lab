# 08 - User Account Deletion Detection

## Objective

The objective of this detection is to identify user account deletion activity on Windows systems that may indicate unauthorized account manipulation, defense evasion, insider threats, or attacker post-compromise actions.

User account deletion is a legitimate administrative activity performed during employee offboarding, account cleanup, or system maintenance. However, threat actors may delete accounts after gaining access to a system in order to remove evidence, disable legitimate user access, eliminate persistence mechanisms, or cover their tracks following malicious activity.

By monitoring Windows User Account Deletion events, security analysts can detect potentially suspicious account removal activity and investigate systems that may have been compromised.

---

## MITRE ATT&CK Mapping

| Field          | Value                     |
| -------------- | ------------------------- |
| Technique ID   | T1070                     |
| Technique Name | Indicator Removal on Host |
| Tactic         | Defense Evasion           |
| Severity Level | Medium                    |

---

## Data Source

| Field             | Value                               |
| ----------------- | ----------------------------------- |
| Log Source        | Windows Security Logs               |
| Log Provider      | Microsoft Windows Security Auditing |
| Event ID          | 4726                                |
| Event Description | A User Account Was Deleted          |

---

## Attack Simulation

### Scenario

To simulate account manipulation and potential defense evasion activity, a local user account was created and subsequently deleted using administrative privileges on a Windows endpoint.

### Steps Performed

1. Opened Command Prompt as Administrator.
2. Created a test user account.
3. Verified that the account was successfully created.
4. Deleted the test user account.
5. Windows generated a User Account Deletion event.
6. Windows recorded the activity as Event ID 4726 in the Security Event Log.
7. Splunk Universal Forwarder collected and forwarded the logs to Splunk Enterprise.
8. The events were analyzed to validate the detection logic.

### Commands Executed

```cmd
net user TestUser Password@123 /add
net user TestUser /delete
```

### Verification Commands

```cmd
net user TestUser
```

---

## Detection Logic

This detection monitors Windows Security Event ID 4726, which indicates that a user account has been deleted from the system.

Threat actors may delete user accounts after obtaining access to a system in order to remove evidence, disable legitimate accounts, clean up persistence mechanisms, or conceal malicious activity.

The detection identifies deleted user accounts and provides visibility into account removal activity for further investigation.

### Detection Conditions

* Monitor Event ID 4726
* Identify deleted user accounts
* Record the account responsible for the deletion
* Record the deleted account name
* Track the source system where the deletion occurred

### Detection Threshold

* Any User Account Deletion Event (Event ID 4726)

### Security Objective

Identify unauthorized or suspicious account deletion activity that may indicate defense evasion, insider threats, or attacker post-compromise actions.

---

## SPL Query

```spl
index="main" EventCode=4726
| table _time ComputerName
```

### Query Breakdown

| Command        | Purpose                               |
| -------------- | ------------------------------------- |
| EventCode=4726 | Filters user account deletion events  |
| table          | Displays relevant fields for analysis |

---

## False Positives

Legitimate account deletion activity may generate alerts, including:

* Employee offboarding processes
* Temporary account cleanup
* Test account removal
* System administration activities
* Lab environment maintenance

---

## Remediation

1. Verify whether the account deletion was authorized.
2. Review the user account responsible for the deletion.
3. Investigate the deleted account and its recent activity.
4. Determine whether the deleted account had elevated privileges.
5. Review authentication logs prior to account deletion.
6. Restore the account if deletion was unauthorized.
7. Investigate related account manipulation activity.
8. Perform additional threat hunting for signs of compromise or defense evasion.

---

