# 02 - Successful Login After Multiple Failed Logins

## Objective

The objective of this detection is to identify successful authentication events that occur after multiple failed login attempts against the same user account.

This behavior may indicate a successful brute-force attack, password spraying attack, credential stuffing attempt, or unauthorized access to a user account.

By correlating failed login events (Event ID 4625) with successful login events (Event ID 4624), security analysts can identify accounts that may have been compromised and prioritize them for immediate investigation.

---

## MITRE ATT&CK Mapping

| Field | Value |
|---------|---------|
| Technique ID | T1110 |
| Technique Name | Brute Force |
| Tactic | Credential Access |
| Severity Level | High |

---

## Data Source

| Field | Value |
|---------|---------|
| Log Source | Windows Security Logs |
| Log Provider | Microsoft Windows Security Auditing |
| Event IDs | 4624, 4625 |
| Event Description | Successful Logon, Failed Logon |

---

## Attack Simulation

### Scenario

To simulate a successful brute-force attack scenario, multiple failed login attempts were generated before a successful authentication event was recorded for the same user account.

### Steps Performed

1. Logged out of the Windows user account.
2. Entered an incorrect password multiple times.
3. Generated several failed login events (Event ID 4625).
4. Successfully authenticated using the correct password.
5. Generated a successful login event (Event ID 4624).
6. Windows recorded all authentication events in the Security Event Log.
7. Splunk Universal Forwarder collected and forwarded the logs to Splunk Enterprise.
8. The events were analyzed to validate the detection logic.

---

## Detection Logic

This detection correlates failed login events (Event ID 4625) with successful login events (Event ID 4624) for the same account.

A successful authentication occurring after multiple failed login attempts may indicate that an attacker has successfully guessed valid credentials and gained access to the system.

The detection identifies accounts that exceed the failed login threshold and subsequently generate a successful authentication event.

### Detection Conditions

* Monitor Event ID 4625 (Failed Logon)
* Monitor Event ID 4624 (Successful Logon)
* Group events by Account Name
* Count failed login attempts
* Verify presence of successful login event
* Trigger when failed login threshold is exceeded and a successful login occurs

### Detection Threshold

* More than **3 failed login attempts**
* At least **1 successful login event**

### Security Objective

Identify potentially compromised accounts where an attacker may have successfully gained access after repeated authentication failures.

---

## SPL Query

```spl
index="main" (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) as Failed_Logins count(eval(EventCode=4624)) as Successful_Logins by Account_Name
| where Failed_Logins > 3 AND Successful_Logins > 0
| sort - Failed_Logins
