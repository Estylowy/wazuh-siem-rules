# 🛡️ Wazuh SIEM — Custom Detection Rules

**Author:** Mateusz Rusnak  
**Stack:** Wazuh 4.7+, Python 3.12, MITRE ATT&CK  
**Status:** Production-ready rules, lab-tested

> Custom Wazuh ruleset covering SSH brute-force, web attack detection, privilege escalation, lateral movement and Windows event anomalies — with a Python CLI tester to simulate and validate each rule.

---

## 📁 Project Structure

```
wazuh-siem-rules/
├── rules/
│   └── rusnak_custom_rules.xml     # 20 custom detection rules (IDs 10500–10590)
├── decoders/
│   └── rusnak_decoders.xml         # Custom log decoders (app logs, anti-cheat, proxy)
├── wazuh_rule_tester.py            # CLI tool: simulate alerts + live API watcher
└── README.md
```

---

## 🔍 Detection Categories

| Rule IDs   | Category                    | MITRE ATT&CK        | Max Level |
|------------|-----------------------------|---------------------|-----------|
| 10500–10505 | SSH Brute-Force             | T1110.001, T1078    | 14        |
| 10520–10525 | Web Login Anomalies         | T1110.001, T1595    | 10        |
| 10540–10544 | Privilege Escalation        | T1548.003, T1136    | 12        |
| 10560–10562 | Lateral Movement / Recon    | T1046, T1021        | 10        |
| 10580–10584 | Windows Event Anomalies     | T1110.001, T1543    | 10        |

---

## ⚡ Key Rules

### SSH Brute-Force (10501)
Triggers after **5 failed SSH logins in 60 seconds from the same IP**.  
Level 14 variant (10502) triggers at 20+ — indicating automated tooling.

### Credential Compromise Signal (10503)
SSH **success** from an IP that just triggered brute-force rule — highest-confidence indicator of a compromised credential.

### Web Scanner Detection (10523)
Matches `User-Agent` against known tools: `sqlmap`, `nikto`, `nuclei`, `gobuster`, `hydra`, `zaproxy`, `acunetix`.

### Privilege Escalation Chain (10541 → 10542 → 10544)
- Single sudo failure → level 8  
- 5+ sudo failures in 2 min → level 12  
- User added to `sudo`/`wheel` group → level 12

### Internal Network Scan (10561)
Detects RFC1918-source scanning — flags possible **compromised internal host** or lateral movement attempt.

---

## 🚀 Installation on Wazuh Manager

```bash
# 1. Copy rules to Wazuh rules directory
sudo cp rules/rusnak_custom_rules.xml /var/ossec/etc/rules/

# 2. Copy decoders
sudo cp decoders/rusnak_decoders.xml /var/ossec/etc/decoders/

# 3. Validate XML syntax
sudo /var/ossec/bin/ossec-logtest -t

# 4. Restart Wazuh manager
sudo systemctl restart wazuh-manager

# 5. Verify rules loaded
sudo /var/ossec/bin/ossec-logtest
# Paste a test log line and check if rule fires
```

### ossec.conf — point Wazuh to custom rules
```xml
<ossec_config>
  <ruleset>
    <rule_dir>etc/rules</rule_dir>
    <decoder_dir>etc/decoders</decoder_dir>
  </ruleset>
</ossec_config>
```

---

## 🧪 Testing Rules

### Simulate all alert categories
```bash
python3 wazuh_rule_tester.py --test-all
```

### Test a specific category
```bash
python3 wazuh_rule_tester.py --category ssh
python3 wazuh_rule_tester.py --category web
python3 wazuh_rule_tester.py --category privesc
python3 wazuh_rule_tester.py --category lateral
python3 wazuh_rule_tester.py --category windows
```

### Generate test log file (feed to Wazuh agent)
```bash
python3 wazuh_rule_tester.py --generate-logs
# → writes to /tmp/rusnak_wazuh_test.log
# Add to ossec.conf:
# <localfile><location>/tmp/rusnak_wazuh_test.log</location><log_format>syslog</log_format></localfile>
```

### Watch live alerts via Wazuh REST API
```bash
# Get auth token first
TOKEN=$(curl -su admin:admin -k -X POST \
  https://WAZUH_HOST:55000/security/user/authenticate \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# Watch live
python3 wazuh_rule_tester.py --live --wazuh-host 192.168.1.10 --token $TOKEN
```

---

## 🧠 Design Decisions

**Why frequency-based rules?**  
Single events generate noise. Rules 10501, 10521, 10542 use `<frequency>` + `<timeframe>` to correlate repeated events — reducing false positives while catching real attacks.

**Why `<same_source_ip/>`?**  
Ensures correlation only fires when failures come from the *same attacker IP*, not across unrelated sources.

**Why MITRE ATT&CK IDs?**  
Wazuh supports MITRE tagging natively. Tagged alerts feed directly into threat reports and compliance dashboards without extra mapping.

**Rule ID range 10500–10590**  
Wazuh reserves IDs below 100000 for custom rules. IDs 10500+ are safely above built-in ranges (1–9999 Wazuh core, 10000–10499 often used by community rules).

---

## 📊 Alert Levels Reference

| Level | Meaning                          | Example                        |
|-------|----------------------------------|--------------------------------|
| 3–4   | Low — informational              | Single auth failure            |
| 5–7   | Medium — worth investigating     | SSH failure, sudo use          |
| 8–11  | High — likely malicious          | Brute-force, scanner detected  |
| 12–14 | Critical — immediate response    | Credential compromise, rootkit |

---

## 🔗 References

- [Wazuh Ruleset Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/)
- [MITRE ATT&CK — Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [Wazuh REST API](https://documentation.wazuh.com/current/user-manual/api/reference.html)
