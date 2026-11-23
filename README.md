# Active Directory Attack & Detection Lab

This is my Active Directory security lab, built from scratch to practise the full
cycle an attacker and a defender go through: **build a realistic domain, attack
it, and then detect the attacks in the logs.** It extends my
[SOC home lab](https://github.com/thyranystrom/home-lab) with an identity/AD focus.

Everything here is run in an **isolated, offline lab** (VirtualBox host-only
network). Nothing is pointed at real systems. The deliberately weak passwords in
the scripts and reports exist only so the lab is reproducible — never reuse them.

## Environment
| Role | Host | IP | OS |
|---|---|---|---|
| Domain controller | DC01.lab.local | 192.168.56.10 | Windows Server 2022 (Eval) |
| Domain client | DESKTOP-S3QQCUD | 192.168.56.11 | Windows 11 Enterprise (Eval) |
| Attacker | kali | 192.168.56.12 | Kali Linux |

The domain `lab.local` and all its users, groups and seeded weaknesses are built
from one idempotent PowerShell script, so the whole lab can be torn down and
rebuilt in minutes:

- [`build-lab-ad.ps1`](./build-lab-ad.ps1) — creates ~24 users, a Kerberoastable
  service account (`svc_sql`), a password left in an account description, a
  dangerous nested group (`IT-Support` → `Domain Admins`), and two accounts that
  share a weak password.

## What I did

**Attacked** the domain from Kali, starting from a single low-privileged user:
- Mapped attack paths to Domain Admins with **BloodHound**.
- **Kerberoasting** — recovered a service account's password offline.
- **Password spraying** — found weak, shared passwords.

**Detected** the same attacks on the domain controller:
- Isolated the Kerberoasting ticket from high-volume 4769 noise by filtering on
  **RC4 (0x17)**.
- Found that the Kerberos auth events were **not audited by default**, enabled
  the audit policy, and re-ran the attack to capture the **4771** spray signature
  (many failures from one source, with the valid accounts absent).

## Reports
Each report is a full, reproducible write-up — environment, exact commands,
captured log evidence, MITRE ATT&CK mapping, and remediation (done with the help of Claude):

- [Incident Report #3 — Kerberoasting](./report3.md)
  *(T1087.002, T1558.003, T1110.002, T1078.002)*
- [Incident Report #4 — BloodHound attack path & password spraying](./report4.md)
  *(T1087.002, T1069.002, T1110.003, T1078.002)*

## Key takeaways
- A single low-privileged domain account is enough to recover service-account
  credentials and to find a path to Domain Admins.
- Detection is about **filtering signal from noise** (e.g. RC4 service tickets),
  not just about whether an event exists.
- **You cannot detect what you do not log** — confirming the right audit policy
  is on is the first step of any detection.

## Next
Phase 3 (in progress): forward the domain controller's security logs to
**Microsoft Sentinel** and re-implement the filters above as **KQL detection
rules**, as detection-as-code.
