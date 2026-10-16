# Sample logs

All data is **fictional**. IPs come from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), domains use `example.*` or obviously fake names, and users are generic. Syslog-format files have no
year, so analyse them with `--year 2024`.

| File | Contents | Expected highlights |
|---|---|---|
| `ssh_auth.log` | SSH logins, 47-failure brute force then success, password spraying | RULE-002, 003, 004 |
| `linux_auth.log` | sudo, PAM failures, invalid user | RULE-001 |
| `apache_access.log` / `nginx_access.log` | Benign browsing plus SQLi, XSS, traversal, command injection, sensitive paths, 404/403 floods, sqlmap UA | RULE-006 to 013 |
| `windows_auth.log` | 4625 failures, 4624 RDP success, privilege and account events | RULE-002, 004 |
| `firewall_portscan.log` | UFW blocks across 30 ports | RULE-005 |
| `ioc_sample.log` | URLs, hashes, CVE, email, IPv6, domains, paths | RULE-014 to 023 |
| `benign_traffic.log` | Normal traffic incl. false-positive traps | **no alerts** |
