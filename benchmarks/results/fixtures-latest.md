## Overall

- Recall: 10/10 (100%)
- False positive rate: 0/8 (0%)

### Validators + replay (live fixture app)

- Recall (planted vulns confirmed): 5/5 (100%)
- False positive rate (safe probes incorrectly confirmed): 0/5 (0%)

| Probe | Expected | Status | Outcome |
|---|---|---|---|
| reflected_xss | vulnerable | verified | TP |
| safe_search_escaped | safe | unverified | TN |
| open_redirect | vulnerable | verified | TP |
| safe_redirect_allowlisted | safe | unverified | TN |
| path_traversal | vulnerable | verified | TP |
| safe_download_allowlisted | safe | unverified | TN |
| expression_injection | vulnerable | verified | TP |
| safe_calc_fixed | safe | unverified | TN |
| idor_profile | vulnerable | verified | TP |
| safe_profile_own_only | safe | unverified | TN |

### Network engine (real nmap, real loopback sockets)

- Recall (planted vulns confirmed): 1/1 (100%)
- False positive rate (safe probes incorrectly confirmed): 0/1 (0%)

| Probe | Expected | Status | Outcome |
|---|---|---|---|
| exposed_redis_port | vulnerable | verified | TP |
| rdp_closed_not_flagged | safe | unverified | TN |

### Mobile engine (real zip/AXML binary; synthetic manifest content)

- Recall (planted vulns confirmed): 4/4 (100%)
- False positive rate (safe probes incorrectly confirmed): 0/2 (0%)

| Probe | Expected | Status | Outcome |
|---|---|---|---|
| apk_debuggable | vulnerable | verified | TP |
| apk_cleartext_traffic | vulnerable | verified | TP |
| apk_exported_service_no_permission | vulnerable | verified | TP |
| apk_launcher_not_flagged | safe | unverified | TN |
| apk_permission_guarded_not_flagged | safe | unverified | TN |
| apk_embedded_aws_key | vulnerable | verified | TP |
