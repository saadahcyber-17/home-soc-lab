# 07 - Scheduled Task Creation Detection

## Objective

The objective of this detection is to identify newly created Windows Scheduled Tasks that may indicate unauthorized persistence, privilege escalation, malware execution, or attacker post-compromise activity.

Scheduled Tasks are legitimate Windows features used to automate administrative and maintenance operations. However, threat actors frequently abuse Scheduled Tasks to establish persistence, execute malicious payloads, evade detection, and maintain long-term access to compromised systems.

By monitoring Scheduled Task creation events, security analysts can detect potentially unauthorized task creation activity and investigate systems that may have been compromised.

---

## MITRE ATT&CK Mapping

| Field          | Value                             |
| -------------- | --------------------------------- |
| Technique ID   | T1053.005                         |
| Technique Name | Scheduled Task                    |
| Tactic         | Persistence, Privilege Escalation |
| Severity Level | High                              |

---

## Data Source

| Field             | Value                           |
| ----------------- | ------------------------------- |
| Log Source        | Task Scheduler Operational Logs |
| Log Provider      | Microsoft-Windows-TaskScheduler |
| Event ID          | 4698                            |
| Event Description | Task Registered                 |

---

## Attack Simulation

### Scenario

To simulate persistence activity, a new Windows Scheduled Task was created using administrative privileges on a Windows endpoint.

### Steps Performed

1. Opened Command Prompt as Administrator.
2. Executed a command to create a new Scheduled Task.
3. Windows registered the task with Task Scheduler.
4. Windows generated a Task Registration event.
5. Windows recorded the activity as Event ID 4698 in the Task Scheduler Operational Log.
6. Splunk Universal Forwarder collected and forwarded the logs to Splunk Enterprise.
7. The events were analyzed to validate the detection logic.

### Commands Executed

```cmd
schtasks /create /tn "TestTask" /tr "cmd.exe" /sc onlogon
```

### Verification Commands

```cmd
schtasks /query /tn "TestTask"
```

---

## Detection Logic

This detection monitors Task Scheduler Event ID 106, which indicates that a new Scheduled Task has been registered on the system.

Threat actors frequently create Scheduled Tasks after obtaining access to a system in order to establish persistence, execute malware automatically, and maintain long-term access to compromised environments.

The detection identifies newly registered Scheduled Tasks and provides visibility into task creation activity for further investigation.

### Detection Conditions

* Monitor Event ID 4698
* Identify newly created Scheduled Tasks
* Record the task name
* Track the source system where the task was created
* Identify the user responsible for task creation

### Detection Threshold

* Any Scheduled Task Creation Event (Event ID 4698)

### Security Objective

Identify unauthorized Scheduled Task creation activity that may indicate persistence mechanisms, malware deployment, or attacker post-compromise actions.

---

## SPL Query

```spl
index="main" EventCode=4698
| table _time ComputerName

```

### Query Breakdown

| Command       | Purpose                                |
| ------------- | -------------------------------------- |
| EventCode=4698 | Filters Scheduled Task creation events |
| table         | Displays relevant fields for analysis  |

---

## False Positives

Legitimate Scheduled Task creation activity may generate alerts, including:

* Software installations and updates
* Windows maintenance tasks
* IT administration activities
* Enterprise management tools
* Backup and monitoring solutions

---

## Remediation

1. Verify whether the Scheduled Task creation was authorized.
2. Review the task name and configured action.
3. Investigate the user account responsible for task creation.
4. Validate the executable or script associated with the task.
5. Determine whether the task provides persistence mechanisms.
6. Disable and remove unauthorized Scheduled Tasks.
7. Investigate related system activity for signs of compromise.
8. Perform additional threat hunting for persistence techniques.

---


