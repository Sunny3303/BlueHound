# BlueHound Detection Catalog

Every rule across all five detection categories is documented here. Each entry includes severity, MITRE technique, detection logic, evidence fields, a real JSON example, and remediation steps.

---

## Category A — Privilege & Identity Exposure

Category A detects misconfigured, stale, or improperly privileged accounts and access control entries that expand the attack surface without necessarily providing an immediate kill path.

---

### A1 — Excessive Local Administrator Rights

**Severity:** HIGH  
**MITRE:** T1078 (Valid Accounts)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled, non-Tier-0 user:
    admin_count = |admin_to_computers[user.sid]|
    If admin_count >= 10:
        Emit HIGH finding
```

The threshold of 10 computers is configurable via `EXCESSIVE_ADMIN_THRESHOLD` in `category_a.py`. The check excludes machine accounts (`$`-suffixed names) and Tier-0 accounts, since administrative rights on privileged accounts are expected.

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `user_sid` | string | SID of the over-privileged user |
| `user_name` | string | SAM account name |
| `computer_count` | integer | Number of computers where user has AdminTo |
| `sample_computers` | list[string] | SAM names of up to 5 affected computers |

**Example Finding JSON:**

```json
{
  "id": "a1-priv-jdoe-8f3a",
  "category": "privilege_exposure",
  "severity": "high",
  "confidence": "explicit",
  "title": "Excessive Local Admin: jdoe has admin rights on 47 computers",
  "description": "jdoe has administrator access to 47 computers exceeding allowed threshold.",
  "affected_principals": ["S-1-5-21-1234-5678-9012-1001"],
  "evidence": {
    "type": "graph_relationship",
    "raw_data": {
      "user_sid": "S-1-5-21-1234-5678-9012-1001",
      "user_name": "jdoe",
      "computer_count": 47,
      "sample_computers": ["WS001", "WS002", "SRV-APP01", "SRV-APP02", "SRV-FIN01"]
    }
  },
  "mitre_techniques": ["T1078"]
}
```

**Remediation:**

Review all AdminTo relationships for the flagged account. Use tiered administration — privileged actions should use dedicated Tier-1 or Tier-2 admin accounts, not the user's daily-driver account. Remove admin rights from workstations where the user does not require them. Consider using Local Administrator Password Solution (LAPS) to prevent lateral movement even if admin rights exist.

---

### A2 — Orphaned Privileged Accounts

**Severity:** HIGH  
**MITRE:** T1078 (Valid Accounts)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
threshold = now() - 90 days

For each enabled, Tier-0 user:
    If user.last_logon is None OR user.last_logon < threshold:
        Emit HIGH finding
```

Tier-0 users include those directly in Domain Admins, Enterprise Admins, or any other Tier-0 group as determined by the transitive group closure in `DetectionContext`.

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `user_sid` | string | SID of the orphaned account |
| `user_name` | string | SAM account name |
| `admin_count` | integer | Value of the AD `adminCount` attribute |
| `days_since_logon` | integer or "never" | Days since last logon, or "never" if null |

**Example Finding JSON:**

```json
{
  "id": "a2-priv-svcadmin-c2a1",
  "category": "privilege_exposure",
  "severity": "high",
  "title": "Orphaned Privileged Account: svcadmin_legacy",
  "description": "Privileged account inactive for extended period.",
  "evidence": {
    "raw_data": {
      "user_sid": "S-1-5-21-1234-5678-9012-1099",
      "user_name": "svcadmin_legacy",
      "admin_count": 1,
      "days_since_logon": 412
    }
  },
  "remediation": "Disable or delete the orphaned privileged account 'svcadmin_legacy'..."
}
```

**Remediation:**

Disable the account immediately and initiate a review process. If the account is legitimately needed (e.g. break-glass scenario), enforce a password reset, remove from all non-essential groups, and move to a separate OU with stricter monitoring. Inactive privileged accounts should be disabled after 90 days by policy.

---

### A3 — Hidden Privileged Membership

**Severity:** HIGH  
**MITRE:** T1484.001 (Domain Policy Modification)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled user where admin_count == 0:
    If user.sid in tier0_sids:  # via transitive group closure
        Emit HIGH finding with the Tier-0 groups through which membership flows
```

This rule catches accounts that BloodHound's AdminSDHolder would not flag because the `adminCount` attribute has not been set, yet the account has effective Tier-0 membership through nested groups.

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `user_sid` | string | SID of the user |
| `tier0_groups` | list[string] | Group names through which Tier-0 membership flows |
| `admin_count` | integer | Always 0 for this rule (the hidden nature of the issue) |

**Example Finding JSON:**

```json
{
  "id": "a3-priv-helpdesk1-d4f2",
  "category": "privilege_exposure",
  "severity": "high",
  "title": "Hidden Privileged Membership: helpdesk1",
  "description": "User gains Tier-0 access via nested membership without admin_count flag.",
  "evidence": {
    "raw_data": {
      "user_sid": "S-1-5-21-1234-5678-9012-2001",
      "tier0_groups": ["IT-Management", "Domain Admins"],
      "admin_count": 0
    }
  }
}
```

**Remediation:**

Remove the account from the intermediate group that grants Tier-0 membership. Run `sdprop` to ensure the `adminCount` attribute is correctly populated. Audit all nested group membership paths from non-privileged groups into Tier-0 groups using BloodHound.

---

### A4 — Dangerous ACEs on Tier-0 Objects

**Severity:** CRITICAL  
**MITRE:** T1484.001 (Domain Policy Modification)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
DANGEROUS = {"GenericAll", "WriteDACL", "WriteOwner"}

For each enabled, non-Tier-0 user:
    For each ACE where ace.trustee == user.sid:
        If ace.right_name in DANGEROUS and context.is_tier0(ace.target):
            Emit CRITICAL finding
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `principal_sid` | string | SID of the user holding the dangerous ACE |
| `target_sid` | string | SID of the Tier-0 object being modified |
| `right_name` | string | One of GenericAll, WriteDACL, WriteOwner |

**Example Finding JSON:**

```json
{
  "id": "a4-priv-analyst1-ff01",
  "category": "privilege_exposure",
  "severity": "critical",
  "title": "Dangerous ACE on Tier-0: analyst1 has WriteDACL",
  "description": "Dangerous permission on Tier-0 object enables privilege escalation.",
  "evidence": {
    "raw_data": {
      "principal_sid": "S-1-5-21-1234-5678-9012-3001",
      "target_sid": "S-1-5-21-1234-5678-9012-512",
      "right_name": "WriteDACL"
    }
  }
}
```

**Remediation:**

Remove the dangerous ACE from the Tier-0 object's DACL immediately. Investigate how the ACE was granted — this is frequently caused by broad OU delegation that was applied to sub-containers. Restrict DACL edit permissions on Tier-0 objects to only the `SYSTEM` account and designated Tier-0 admins.

---

## Category B — Kerberos Abuse

Category B identifies accounts whose Kerberos configuration enables offline credential attacks, most of which require only a low-privilege domain foothold to initiate.

---

### B1 — Kerberoastable Service Accounts

**Severity:** HIGH (Tier-0 accounts) / MEDIUM (others)  
**MITRE:** T1558.003 (Kerberoasting)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled user:
    If user has SPNs AND name does not end with "$" AND name != "krbtgt":
        severity = HIGH if is_tier0(user.sid) else MEDIUM
        Emit finding with SPN list
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `user_sid` | string | SID of the kerberoastable account |
| `user_name` | string | SAM account name |
| `spns` | list[string] | All registered SPNs |
| `spn_count` | integer | Total number of SPNs |
| `is_tier0` | boolean | Whether account is Tier-0 (drives severity) |

**Example Finding JSON:**

```json
{
  "id": "b1-kerb-sqlsvc01-a3c2",
  "category": "kerberos_abuse",
  "severity": "medium",
  "title": "Kerberoastable Account: sqlsvc01",
  "description": "Account 'sqlsvc01' has 2 SPN(s) and is vulnerable to Kerberoasting. SPNs: MSSQLSvc/sql01.corp.local:1433, MSSQLSvc/sql01.corp.local",
  "evidence": {
    "raw_data": {
      "user_sid": "S-1-5-21-1234-5678-9012-4001",
      "user_name": "sqlsvc01",
      "spns": ["MSSQLSvc/sql01.corp.local:1433", "MSSQLSvc/sql01.corp.local"],
      "spn_count": 2,
      "is_tier0": false
    }
  },
  "remediation": "Use a long, random password (25+ chars) for 'sqlsvc01' to make offline cracking infeasible..."
}
```

**Remediation:**

Assign a random 25+ character password to the service account, making offline cracking infeasible. Migrate the account to a Group Managed Service Account (gMSA) where possible — gMSAs auto-rotate their 120-character passwords. If the SPN is not required, remove it.

---

### B2 — AS-REP Roastable Users

**Severity:** HIGH (Tier-0 accounts) / MEDIUM (others)  
**MITRE:** T1558.004 (AS-REP Roasting)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled user:
    If user.kerberos_preauth_not_required == True:
        severity = HIGH if is_tier0(user.sid) else MEDIUM
        Emit finding
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `user_sid` | string | SID of the AS-REP roastable account |
| `user_name` | string | SAM account name |
| `kerberos_preauth_not_required` | boolean | Always True for this rule |
| `is_tier0` | boolean | Whether account is Tier-0 |

**Example Finding JSON:**

```json
{
  "id": "b2-kerb-legacy_svc-b1d4",
  "category": "kerberos_abuse",
  "severity": "medium",
  "title": "AS-REP Roastable: legacy_svc",
  "description": "User 'legacy_svc' does not require Kerberos pre-authentication and is vulnerable to AS-REP Roasting.",
  "evidence": {
    "raw_data": {
      "user_sid": "S-1-5-21-1234-5678-9012-5001",
      "user_name": "legacy_svc",
      "kerberos_preauth_not_required": true,
      "is_tier0": false
    }
  }
}
```

**Remediation:**

Enable Kerberos pre-authentication by unchecking "Do not require Kerberos preauthentication" in Active Directory Users and Computers. This setting exists for legacy compatibility and should almost never be disabled on modern environments.

---

### B3 — SPN on Human Accounts

**Severity:** MEDIUM  
**MITRE:** T1558.003 (Kerberoasting)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled user with SPNs where name does not end with "$" and name != "krbtgt":
    If NOT _is_service_account(user.sam_account_name):
        Emit MEDIUM finding

_is_service_account checks for: svc_ prefix, service_ prefix, or common
service-name substrings (sql, iis, apache, nginx, tomcat, jboss, weblogic, websphere)
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `user_sid` | string | SID of the human account |
| `user_name` | string | SAM account name |
| `spns` | list[string] | Registered SPNs |
| `spn_count` | integer | Total SPN count |

**Remediation:**

Remove the SPN from the human account. Create a dedicated service account or gMSA to host the SPN. Human accounts use memorable passwords that are far more susceptible to offline cracking than randomly generated service account credentials.

---

## Category C — Delegation Abuse

Category C finds delegation misconfigurations that allow impersonation of users or facilitate machine account creation attacks.

---

### C1 — Unconstrained Delegation

**Severity:** HIGH  
**MITRE:** T1134.001 (Token Impersonation/Theft)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled computer:
    If computer.unconstrained_delegation == True:
        If NOT _is_domain_controller(computer, context):
            Emit HIGH finding
```

Domain controllers are excluded because they legitimately require unconstrained delegation. DC detection uses three heuristics: distinguished name contains `ou=domain controllers`, operating system contains `domain controller`, or hostname starts with `dc` or contains `-dc`.

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `computer_sid` | string | SID of the misconfigured computer |
| `computer_name` | string | SAM account name |
| `unconstrained_delegation` | boolean | Always True |
| `is_domain_controller` | boolean | Always False (DCs excluded) |
| `operating_system` | string | OS string from AD |

**Example Finding JSON:**

```json
{
  "id": "c1-del-srvapp01-e2b3",
  "category": "delegation_abuse",
  "severity": "high",
  "title": "Unconstrained Delegation: SRV-APP01$",
  "description": "Computer 'SRV-APP01$' allows unconstrained delegation enabling impersonation of ANY authenticating user.",
  "evidence": {
    "raw_data": {
      "computer_sid": "S-1-5-21-1234-5678-9012-6001",
      "computer_name": "SRV-APP01$",
      "unconstrained_delegation": true,
      "is_domain_controller": false,
      "operating_system": "Windows Server 2019"
    }
  }
}
```

**Remediation:**

Disable unconstrained delegation in the computer account's delegation settings. Replace with constrained delegation or RBCD configured to the minimum required services. Mark all Tier-0 accounts with "Account is sensitive and cannot be delegated" to prevent TGT capture even if unconstrained delegation exists on other machines.

---

### C2 — Resource-Based Constrained Delegation to Tier-0

**Severity:** HIGH  
**MITRE:** T1134.001 (Token Impersonation/Theft)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled, non-Tier-0 computer with allowed_to_delegate_to SPNs:
    Parse target hostnames from SPNs
    If any parsed hostname matches a Tier-0 computer (by SAM name):
        Emit HIGH finding
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `source_computer_sid` | string | SID of the delegating computer |
| `target_tier0` | boolean | Always True |
| `target_count` | integer | Number of Tier-0 computers in delegation targets |
| `target_spns` | list[string] | Raw SPN strings from the delegation attribute |

**Remediation:**

Review and restrict the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. Remove the non-Tier-0 computer from the ACL of Tier-0 systems. Ensure that RBCD is configured only to the minimum required service accounts and never grants lateral access toward Tier-0 assets.

---

### C3 — Machine Account Quota Enabled

**Severity:** MEDIUM  
**MITRE:** T1098 (Account Manipulation)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
domain_info = view.get_domain_info()
quota = domain_info["ms-ds-machineaccountquota"]
If quota > 0:
    Emit MEDIUM finding
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `machine_account_quota` | integer | Current quota value (default is 10 in AD) |
| `domain_fqdn` | string | Affected domain FQDN |

**Remediation:**

Set `ms-DS-MachineAccountQuota` to 0 using: `Set-ADDomain -Identity <domain> -Replace @{"ms-DS-MachineAccountQuota"="0"}`. Delegate machine account creation only to specific service accounts or OUs via DACL rather than relying on the domain-wide quota.

---

## Category D — ADCS Exploitation

Category D analyzes Active Directory Certificate Services data loaded separately from the BloodHound graph. ADCS findings carry the highest ADCS bias (1.30×) in the risk engine because certificate-based attacks provide persistent, stealthy domain compromise.

---

### D1 — ESC1: Vulnerable Certificate Template

**Severity:** CRITICAL  
**MITRE:** T1649 (Steal or Forge Authentication Certificates)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each certificate template:
    If template.enrollee_supplies_subject == True
    AND template.client_authentication == True
    AND template.manager_approval_required == False
    AND template.authorized_signatures_required == 0
    AND any non-Tier-0 principal is in template.enrollment_permissions:
        Emit CRITICAL finding
```

ESC1 is the canonical ADCS privilege escalation: a low-privileged user can request a certificate specifying any UPN (including a Domain Admin) as the subject, then use that certificate to authenticate as that user.

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `template_name` | string | Certificate template display name |
| `esc_type` | string | Always "ESC1" |
| `non_privileged_enrollers` | integer | Count of non-Tier-0 principals that can enroll |

**Example Finding JSON:**

```json
{
  "id": "d1-adcs-UserTemplate-f9c1",
  "category": "adcs_abuse",
  "severity": "critical",
  "confidence": "explicit",
  "title": "ESC1: Vulnerable Certificate Template 'UserTemplate'",
  "description": "Template 'UserTemplate' allows subject supply and client authentication without approval. 847 non-privileged principals can enroll certificates.",
  "evidence": {
    "raw_data": {
      "template_name": "UserTemplate",
      "esc_type": "ESC1",
      "non_privileged_enrollers": 847
    }
  }
}
```

**Remediation:**

Disable "Supply in the request" for the subject name (set to "Build from this Active Directory information" instead). If subject supply is required, enable Manager Approval. Audit all templates with this setting using `Certify.exe find /vulnerable`. Consider whether the template is still required at all.

---

### D2 — ESC4: Dangerous Template Permissions

**Severity:** CRITICAL  
**MITRE:** T1649 (Steal or Forge Authentication Certificates)  
**Confidence:** INFERRED

**Detection Logic:**

```
DANGEROUS = {"WriteDACL", "WriteOwner", "GenericAll"}

For each certificate template with client_authentication == True:
    For each ACE on this template:
        If ace.right_name in DANGEROUS AND NOT is_tier0(ace.trustee):
            Emit CRITICAL finding
```

ESC4 allows an attacker with template write rights to modify an otherwise-safe template to introduce ESC1 conditions.

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `template_name` | string | Certificate template name |
| `principal_sid` | string | SID of the principal with dangerous rights |
| `permission` | string | One of WriteDACL, WriteOwner, GenericAll |
| `esc_type` | string | Always "ESC4" |

**Remediation:**

Remove the dangerous ACE from the certificate template's security descriptor. Only PKI Admins and Enterprise Admins should have write access to certificate templates. Review all template permissions using `certsrv.msc` or PowerShell.

---

### D3 — ESC8: NTLM Relay to ADCS Web Enrollment

**Severity:** CRITICAL  
**MITRE:** T1187 (Forced Authentication)  
**Confidence:** INFERRED

**Detection Logic:**

```
For each certificate authority:
    If ca.web_enrollment_enabled == True AND ca.ntlm_allowed == True:
        vulnerable_templates = [t for t in ca.templates if t.client_authentication]
        If vulnerable_templates:
            Emit CRITICAL finding
```

ESC8 allows an attacker to relay an NTLM authentication from any machine account to the CA's web enrollment endpoint and obtain a certificate for that machine account, then use it for further attacks.

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ca_name` | string | Certificate authority name |
| `dns_hostname` | string | CA hostname (relay target) |
| `client_auth_templates` | list[string] | Templates that enable client auth |
| `esc_type` | string | Always "ESC8" |

**Remediation:**

Enforce HTTPS with Extended Protection for Authentication (EPA) on the web enrollment endpoint, or disable NTLM and require Kerberos. Alternatively, disable the web enrollment endpoint (`certsrv`) entirely if not required. This blocks the relay attack surface without disabling the CA.

---

## Category E — Tier-0 Reachability

Category E is the capstone detection layer. It directly traces attack paths from non-privileged principals to Tier-0 assets and is the primary driver of catastrophic and domain-wide exposure classifications.

---

### E1 — Non-Privileged User to Tier-0 Path

**Severity:** CRITICAL (≤3 hops) / HIGH (4–5 hops) / MEDIUM (6+ hops)  
**MITRE:** T1078.003 (Local Accounts), T1484.001 (Domain Policy Modification)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
For each enabled, non-Tier-0 user:
    paths = []
    
    # Check direct ACL abuse
    For each ACE where ace.trustee == user.sid:
        If is_tier0(ace.target):
            paths.append({hop_count: 1, technique: ace.right_name})
    
    # Check AdminTo chain
    For each computer_sid in admin_to_computers[user.sid]:
        If is_tier0(computer_sid):
            paths.append({hop_count: 2, technique: "AdminTo"})
    
    If paths:
        best_path = min(paths, key=lambda p: p.hop_count)
        severity = CRITICAL if hops <= 3 else HIGH if hops <= 5 else MEDIUM
        Emit finding with full path trace
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `start_user_sid` | string | SID of the non-privileged starting user |
| `end_tier0_sid` | string | SID of the Tier-0 target |
| `hop_count` | integer | Number of hops in the best path |
| `path_hops` | list[dict] | Step-by-step path: from, to, technique |
| `attack_primitives` | list[string] | High-level primitive types (ACL_Abuse, AdminTo_Chain) |

**Example Finding JSON:**

```json
{
  "id": "e1-tier0-jsmith-dc01-a9f2",
  "category": "tier0_exposure",
  "severity": "critical",
  "confidence": "explicit",
  "title": "Tier-0 Exposure: jsmith can reach Tier-0 in 1 hop(s)",
  "description": "User 'jsmith' has a privilege escalation path to Tier-0.\n\nAttack Path:\n1. jsmith → DC01 via WriteDACL",
  "evidence": {
    "raw_data": {
      "start_user_sid": "S-1-5-21-1234-5678-9012-7001",
      "end_tier0_sid": "S-1-5-21-1234-5678-9012-1000",
      "hop_count": 1,
      "path_hops": [
        {"from": "jsmith", "to": "DC01", "technique": "WriteDACL"}
      ],
      "attack_primitives": ["ACL_Abuse"]
    }
  },
  "mitre_techniques": ["T1484.001"],
  "remediation": "- Remove or mitigate: WriteDACL"
}
```

**Remediation:**

Each hop in the attack path must be individually mitigated. For ACL abuse hops: remove the dangerous ACE from the target object. For AdminTo hops: remove the admin relationship or move the target computer to a higher tier. Any single hop remediation breaks the kill path.

---

### E2 — Workstation to Domain Controller Admin Path

**Severity:** CRITICAL  
**MITRE:** T1078.003 (Local Accounts)  
**Confidence:** EXPLICIT

**Detection Logic:**

```
dcs = [c for c in computers if c.enabled and is_tier0(c.sid) and "Domain Controller" in c.operating_system]
workstations = [c for c in computers if c.enabled and not is_tier0(c.sid)
                and ("Windows 10" in c.operating_system or "Windows 11" in c.operating_system)]

For each workstation:
    For each dc:
        If dc.sid in admin_to_computers[workstation.sid]:
            Emit CRITICAL finding
```

**Evidence Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `workstation_sid` | string | SID of the workstation with DC admin rights |
| `dc_sid` | string | SID of the target domain controller |
| `path_type` | string | Always "admin_chain" |

**Example Finding JSON:**

```json
{
  "id": "e2-tier0-ws042-dc01-b3e1",
  "category": "tier0_exposure",
  "severity": "critical",
  "title": "Tier-0 Boundary Collapse: WS042$ → DC01",
  "description": "Workstation has administrative access to Domain Controller.",
  "evidence": {
    "raw_data": {
      "workstation_sid": "S-1-5-21-1234-5678-9012-8001",
      "dc_sid": "S-1-5-21-1234-5678-9012-1000",
      "path_type": "admin_chain"
    }
  },
  "mitre_techniques": ["T1078.003"],
  "remediation": "Remove workstation administrative access from Domain Controllers."
}
```

**Remediation:**

Immediately remove the AdminTo relationship between the workstation and the domain controller. This is a critical Tier isolation boundary violation. Investigate how the workstation gained DC admin rights — this is often caused by a misconfigured GPO, a local admin account reuse, or a software deployment tool that propagated credentials inappropriately.

---

## MITRE ATT&CK Mapping Summary

| Rule | Rule ID | MITRE Technique | Sub-Technique |
|------|---------|-----------------|---------------|
| Excessive Local Admin | A1 | T1078 | Valid Accounts |
| Orphaned Privileged Accounts | A2 | T1078 | Valid Accounts |
| Hidden Privileged Membership | A3 | T1484.001 | Domain Policy Modification |
| Dangerous ACEs on Tier-0 | A4 | T1484.001 | Domain Policy Modification |
| Kerberoastable Accounts | B1 | T1558.003 | Kerberoasting |
| AS-REP Roastable | B2 | T1558.004 | AS-REP Roasting |
| SPN on Human Accounts | B3 | T1558.003 | Kerberoasting |
| Unconstrained Delegation | C1 | T1134.001 | Token Impersonation |
| RBCD to Tier-0 | C2 | T1134.001 | Token Impersonation |
| Machine Account Quota | C3 | T1098 | Account Manipulation |
| ESC1 Vulnerable Template | D1 | T1649 | Steal/Forge Auth Certificates |
| ESC4 Template Permissions | D2 | T1649 | Steal/Forge Auth Certificates |
| ESC8 NTLM Relay | D3 | T1187 | Forced Authentication |
| User to Tier-0 Path | E1 | T1078.003, T1484.001 | Local Accounts |
| Workstation to DC | E2 | T1078.003 | Local Accounts |
