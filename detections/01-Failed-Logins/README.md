# 01 - Failed Login Detection

## Objective

The objective of this detection is to identify multiple failed authentication attempts that may indicate a brute-force attack, password spraying attack, unauthorized access attempt, or user account compromise.

This detection monitors Windows Security Event ID **4625** and alerts security analysts when the number of failed login attempts exceeds a defined threshold within a specified time period.

By detecting excessive authentication failures, security teams can investigate suspicious activity, determine whether an attacker is attempting to gain access to an account, and take appropriate remediation actions before a successful compromise occurs.

---

## MITRE ATT&CK Mapping

| Field          | Value             |
| -------------- | ----------------- |
| Technique ID   | T1110             |
| Technique Name | Brute Force       |
| Tactic         | Credential Access |
| Severity Level | Medium            |

---

## Data Source

| Field             | Value                               |
| ----------------- | ----------------------------------- |
| Log Source        | Windows Security Logs               |
| Log Provider      | Microsoft Windows Security Auditing |
| Event ID          | 4625                                |
| Event Description | Failed Logon                        |

---

## Attack Simulation

### Scenario

To simulate a brute-force authentication attack, multiple failed login attempts were intentionally generated on a Windows endpoint.

### Steps Performed

1. Logged out of the Windows user account.
2. Attempted to authenticate using an incorrect password multiple times.
3. Generated several failed login events within a short period of time.
4. Windows recorded each failed authentication attempt as Event ID 4625 in the Security Event Log.
5. The Splunk Universal Forwarder collected the Windows Security Logs and forwarded them to Splunk Enterprise.
6. The events were searched, analyzed, and used to validate the detection logic.

---

## Detection Logic

This detection monitors Windows Security Event ID **4625**, which represents failed authentication attempts.

A high number of failed login attempts against the same account within a short period of time may indicate a brute-force attack, password spraying attack, or unauthorized access attempt.

The detection aggregates failed login events by account name and counts the total number of authentication failures. If the number of failed login attempts exceeds a predefined threshold, the activity is flagged as suspicious and investigated further.

### Detection Conditions

* Monitor Event ID 4625 (Failed Logon)
* Group events by Account Name
* Count failed login attempts
* Trigger when failed attempts exceed the defined threshold

### Detection Threshold

* More than **3 failed login attempts**

### Security Objective

Identify potential credential-based attacks before a successful compromise occurs.

---

## SPL Query

```spl
index="main" EventCode=4625
| stats count by Account_Name
| where count > 3
| sort - count
```

### Query Breakdown

| Command                     | Purpose                                                     |
| --------------------------- | ----------------------------------------------------------- |
| EventCode=4625              | Filters failed login events                                 |
| stats count by Account_Name | Counts failed login attempts per user                       |
| where count > 3             | Filters accounts exceeding the threshold                    |
| sort - count                | Displays accounts with the highest failed login count first |

---

## False Positives

The following legitimate activities may trigger this detection:

- Users entering an incorrect password multiple times.
- Users forgetting their password.
- Service accounts configured with outdated credentials.
- Keyboard layout or Caps Lock issues.
- Automated scripts using incorrect credentials.

---

## Remediation Recommendations

- Implement Multi-Factor Authentication (MFA).
- Configure account lockout policies.
- Enforce strong password requirements.
- Monitor repeated authentication failures.
- Review and disable unused accounts.
- Investigate accounts exhibiting abnormal authentication behavior.
