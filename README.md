# 🔐 Splunk Brute-Force Attack Detection & Analysis

## 📌 Overview

This project demonstrates the detection and analysis of brute-force login attacks using Splunk SIEM. The objective is to identify suspicious authentication activity by analyzing Windows Event Logs, detecting repeated failed login attempts, and creating SOC-style alerts for proactive threat monitoring.

The project focuses on failed authentication events (EventCode 4625) and applies threshold-based detection techniques commonly used in Security Operations Centers (SOCs).

---

## 🎯 Objectives

* Understand brute-force attack behavior
* Analyze Windows authentication logs
* Detect repeated failed login attempts
* Identify malicious source IP addresses
* Discover targeted user accounts
* Monitor attack spikes over time
* Create automated Splunk alerts
* Apply SOC detection and investigation techniques

---

## 🛠 Tools & Technologies

* Splunk Enterprise
* SPL (Search Processing Language)
* Windows Event Logs
* Security Information and Event Management (SIEM)

---

## 📊 Detection Workflow

### Step 1: Verify Data Availability

```spl
index=* sourcetype=*
```

Windows Event Logs:

```spl
index=wineventlog
```

---

### Step 2: Detect Failed Login Attempts

```spl
index=* "failed" OR "failure" OR "invalid login"
```

Windows-specific search:

```spl
index=wineventlog EventCode=4625
```

**EventCode 4625** represents a failed login attempt.

---

### Step 3: Identify Suspicious Source IP Addresses

```spl
index=wineventlog EventCode=4625
| stats count by src_ip
| sort - count
```

This query identifies IP addresses generating the highest number of failed login attempts.

---

### Step 4: Detect Targeted User Accounts

```spl
index=wineventlog EventCode=4625
| stats count by user
| sort - count
```

This query reveals which user accounts are being targeted by attackers.

---

### Step 5: Threshold-Based Brute-Force Detection

```spl
index=wineventlog EventCode=4625
| stats count by src_ip
| where count > 5
```

Detection Rule:

* More than 5 failed login attempts from a single IP address are considered suspicious.

---

### Step 6: Time-Based Attack Monitoring

```spl
index=wineventlog EventCode=4625
| timechart span=5m count by src_ip
```

This helps identify:

* Login attempt spikes
* Automated attack patterns
* Continuous brute-force activity

---

### Step 7: Advanced Detection Logic

```spl
index=wineventlog EventCode=4625
| stats count by src_ip, user
| where count > 5
| sort - count
```

This query detects:

* Source IP addresses
* Targeted users
* Repeated attack patterns

---

### Step 8: Alert Configuration

Create a Splunk Alert:

**Trigger Condition**

```text
Number of Results > 0
```

**Schedule**

```text
Every 5 Minutes
```

**Actions**

* Email Notification
* Webhook Notification

---

## 🚨 SOC Analyst Findings

Potential brute-force attack activity was detected through repeated failed login attempts originating from single IP addresses and targeting multiple user accounts.

Detection logic was implemented using Windows EventCode 4625, statistical aggregation, and threshold-based alerting techniques to identify suspicious authentication behavior.

---

## 🔍 Additional Threat Hunting Queries

### Geo-IP Analysis

```spl
index=wineventlog EventCode=4625
| iplocation src_ip
| stats count by Country
```

### Failed vs Successful Login Comparison

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count by EventCode
```

---

## 📈 Skills Demonstrated

* Splunk SPL Query Development
* Windows Event Log Analysis
* Threat Detection Engineering
* SOC Monitoring
* Security Alerting
* Authentication Log Analysis
* Brute-Force Attack Detection
* Incident Investigation

---

## 📚 Learning Outcomes

* Improved understanding of authentication-based attacks
* Developed practical Splunk investigation skills
* Implemented real-world SOC detection logic
* Gained experience in security monitoring and alert creation

---

## 👨‍💻 Author

Talha

Cybersecurity Enthusiast | SOC Analyst | Splunk SIEM | Threat Detection
