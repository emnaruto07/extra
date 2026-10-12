# adenum

Active Directory enumeration tool for **internal pentests** — built for the classic starting position: on the corp network, **zero credentials**, goal = Domain Admin.

Pure enumeration, zero exploitation. Nothing is modified on any target system.

## Attack path logic

```
NO CREDS ──┬─> AS-REP roasting ────────────> crack hash ──┐
           ├─> Kerberos username oracle ──> valid users   │
           ├─> SMB signing recon ────────> relay targets  ├─> FIRST CREDS
           ├─> Zerologon check ──────────> instant DA(!)  │
           ├─> Spooler/PetitPotam ───────> coercion paths │
           ├─> Anonymous LDAP / null SMB ─> user lists    │
           └─> DNS SRV / AXFR ───────────> DC inventory  │
                                                            v
ANY CREDS ──> full users/groups/computers/trusts/policy
             kerberoastable + AS-REP lists, DA membership
             delegation, GMSA, LAPS read, MAQ, desc intel
```

## Phase 1 — unauthenticated (no lockout risk)

| Check | What it does | OPSEC |
|---|---|---|
| Port sweep (DC + `--cidr` subnet) | top AD/service ports, threaded | TCP connects only |
| rootDSE read | naming contexts, DC hostname/level | anonymous bind |
| Anonymous LDAP | users, AS-REP roastables, SPN accounts | anonymous bind |
| SMB null session | SAMR user enumeration | null session |
| Kerberos username oracle | AS-REQ w/o preauth → PREAUTH_REQUIRED = exists | never counts as failed auth |
| AS-REP roasting | captures hashcat 18200 hashes | no auth events |
| SMB signing check | relay-target list | negotiate only |
| SMBv1 dialect check | EternalBlue-era surface | negotiate only |
| Zerologon (CVE-2020-1472) | non-destructive detection only | 5-6 MSRPC calls |
| Spooler / PetitPotam | pipe reachability only | no coercion performed |
| DNS SRV + AXFR | DC inventory, zone transfer attempt | plain queries |
| SNMP `public` | device inventory leak | UDP gets |

## Phase 2 — authenticated (any valid user)

Full domain dump (users/groups/computers/trusts/policy), then high-value findings:

- AS-REP roastable + kerberoastable accounts
- Domain Admin membership, admin-ish groups
- Unconstrained / S4U delegation, legacy-OS hosts
- `PASSWD_NOTREQD`, cleartext-storage (GMSA), no-preauth users
- Password policy → **spray calibration** (threshold=0 flagged = unlimited spraying)
- LAPS (`ms-Mcs-AdmPwd`) read check
- `ms-DS-MachineAccountQuota` (FakeMachine angle)
- Description-field password intel (`pass`, `svc`, `key`, ...)
- Trust parsing: direction, type, WITHIN_FOREST (cross-domain DA)

## Usage

```bash
pip install ldap3 impacket dnspython

# Phase 1 - no creds
python3 adenum.py --dc-ip 10.0.0.10 --domain corp.local --cidr 10.0.0.0/24 --users users.txt -o client1

# Phase 2 - after first creds
python3 adenum.py --dc-ip 10.0.0.10 --domain corp.local -u jdoe -p 'Pass1!' -o client1
```

Outputs: `<prefix>.asrep.txt` (hashcat -m 18200), `<prefix>.users.txt`, `<prefix>.enum.json` (phase 2 full dump).

## Notes

- Interval attributes normalized across all ldap3 serialization shapes (raw filetime, `str(timedelta)`, ints — see ntlmrelayx-prettyloot for the gory details)
- MSRPC checks (Zerologon/spooler) validated against code paths only — sanity-check on a lab DC before engagement use
- Manual SQLi-style discipline: single-threaded Kerberos by default, 64-thread TCP sweep

## Tests

```bash
python3 test_adenum.py   # 26 unit tests, pure functions, no network needed
```