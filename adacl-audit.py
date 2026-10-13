#!/usr/bin/env python3
"""
adacl-audit - enumerate what YOUR principal can do across AD via ACLs.

Given valid creds, pulls nTSecurityDescriptor on key objects, parses every
ACE with impacket's ldaptypes, and reports dangerous rights applying to you
directly or via groups (GenericAll/WriteDacl/WriteOwner/GenericWrite, SPN /
msDS-KeyCredentialLink / UAC / member writes, Self rights, DCSync extended
rights, ForceChangePassword).

Optional --lootdir <ntlmrelayx -l dir>: enrich trustee names/SIDs offline
from ldapdomaindump JSONs (users/groups/computers) — zero extra LDAP traffic.

ENUM-ONLY: reads nTSecurityDescriptor; performs NO writes.
"""
import argparse
import json
import os
import sys

from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin, bin_to_string

# ---------------------------------------------------------------- constants

R = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE  # shorthand for mask constants
RIGHT = {
    "CreateChild": R.ADS_RIGHT_DS_CREATE_CHILD,
    "DeleteChild": R.ADS_RIGHT_DS_DELETE_CHILD,
    "Self": R.ADS_RIGHT_DS_SELF,
    "ReadProp": R.ADS_RIGHT_DS_READ_PROP,
    "WriteProp": R.ADS_RIGHT_DS_WRITE_PROP,
    "ControlAccess": R.ADS_RIGHT_DS_CONTROL_ACCESS,
}
RIGHT["WriteDacl"] = 0x00040000
RIGHT["WriteOwner"] = 0x00080000
RIGHT["Delete"] = 0x00010000
RIGHT["GenericRead"] = 0x80000000
RIGHT["GenericWrite"] = 0x40000000
RIGHT["GenericAll"] = 0x100F01FF  # full-control mapping for DS objects

# schema property GUIDs (schemaIDGUID) that matter for exploitation
PROP_GUIDS = {
    "bf967a9c-0de6-11d0-a285-00aa003049e2": ("Members property set", "modify group membership"),
    "bf967a0f-0de6-11d0-a285-00aa003049e2": ("Member", "add/remove group members"),
    "f3a64788-da66-11d1-a9da-00c04fb9fbc1": ("servicePrincipalName", "targeted Kerberoast"),
    "5f202010-79bf-11d0-9bd8-00a0c905fbfc": ("msDS-KeyCredentialLink", "shadow credentials"),
    "bf967a90-0de6-11d0-a285-00aa003049e2": ("userAccountControl", "disable preauth / lockout / enable"),
    "3e78cbe8-4c79-4c14-ae15-e1f1bb4d4d2d": ("sAMAccountName", "rename object"),
    "77b598f6-636b-4c46-81f3-f2e2bbd5b7b3": ("gMSA managed password", "read gMSA pwd"),
}
# extended rights (controlAccessRight validAccesses=ControlAccess)
EXT_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Get-Changes", "DCSync (part 1)"),
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Get-Changes-All", "DCSync (secrets)"),
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Get-Changes-In-Filtered-Set", "DCSync (extra)"),
    "00299570-246d-11d0-a7a4-00aa0046a067": ("User-Force-Change-Password", "reset any user's password"),
    "ab721a53-1e2f-11d0-971e-dcbc0d2f0000": ("User-Change-Password", "change password (must know old)"),
    "e48d1f0a-4b47-11d0-a7c7-00c04fd930c9": ("Send-To", "Exchange send-to right"),
    "59ba2f42-79a2-11d0-9020-00c04fc2d3cd": ("General-Information read", "read user info"),
    "bc0ac240-79a9-11d0-9020-00c04fc2d3cd": ("Public-Information read", "read public info"),
    "e8b2aff3-59ab-11d0-afd3-00c04fd930c9": ("Web-Information read", "read web info"),
}
# class-schema GUIDs (for inherited ACEs scoping to a class)
CLASS_GUIDS = {
    "bf967aba-0de6-11d0-a285-00aa003049e2": "user",
    "bf967a9c-0de6-11d0-a285-00aa003049e2": "group",
    "bf967a86-0de6-11d0-a285-00aa003049e2": "computer",
    "bf967aa5-0de6-11d0-a285-00aa003049e2": "organizationalUnit",
    "f30e3bc2-9ff0-11d1-b603-0000f80367c1": "groupPolicyContainer",
    "19195a5a-6da0-11d0-afd3-00c04fd930c9": "domainDNS",
    "ce206604-5846-4a48-8b62-63a25f3a7576": "msDS-GroupManagedServiceAccount",
}
# ADS generic bits -> canonical DS rights mapping (from MS-ADTS)
GENERIC_TO_DS = {
    0x80000000: 0x00020094,  # GenericRead  -> ReadControl|ReadProp|ListObject|...
    0x40000000: 0x00020020,  # GenericWrite-> ReadControl + WriteProp
    0x20000000: 0x00020004,  # GenericExecute-> ReadControl
    0x10000000: 0x000F01FF,  # GenericAll  -> everything
}


def bin2guid(raw):
    try:
        return bin_to_string(bytes(raw)).lower()
    except Exception:
        return None


def bin2sidstr(raw):
    try:
        sid = ldaptypes.LDAP_SID(blob=bytes(raw))
        return sid.formatCanonical()
    except Exception:
        return None


def expand_generic(mask):
    """Map GENERIC_READ/WRITE/EXECUTE/ALL bits to their DS equivalents."""
    out = mask
    if mask & 0x80000000: out |= GENERIC_TO_DS[0x80000000]
    if mask & 0x40000000: out |= GENERIC_TO_DS[0x40000000]
    if mask & 0x20000000: out |= GENERIC_TO_DS[0x20000000]
    if mask & 0x10000000: out |= GENERIC_TO_DS[0x10000000]
    return out & 0x000FFFFF | (mask & 0xF0000000)  # keep generic bits, add DS bits


# ---------------------------------------------------------------- loot load

def load_loot(lootdir):
    """ntlmrelayx/ldapdomaindump loot -> (sid_by_name, name_by_sid) maps."""
    sid_by_name, name_by_sid = {}, {}
    fnames = ["domain_users.json", "domain_groups.json", "domain_computers.json"]
    for fname in fnames:
        path = os.path.join(lootdir, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[-] loot {fname}: {e}")
            continue
        entries = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(entries, list):
            continue
        for entry in entries:
            attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
            name = attrs.get("sAMAccountName")
            sid = attrs.get("objectSid")
            if isinstance(name, list): name = name[0] if name else None
            if isinstance(sid, list): sid = sid[0] if sid else None
            if name and sid:
                sid_by_name[name] = sid
                name_by_sid[sid] = name
    return sid_by_name, name_by_sid


# ---------------------------------------------------------------- SD parse

def parse_sd(raw):
    """nTSecurityDescriptor raw bytes -> (owner_sid, [ACE structures])"""
    try:
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(bytes(raw))
    except Exception:
        return None, []
    owner = None
    if sd["OffsetOwner"] > 0:
        try:
            owner = bin2sidstr(sd["OwnerSid"].getData())
        except Exception:
            owner = None
    aces = []
    if sd["OffsetDacl"] > 0:
        dacl = sd["Dacl"]
        if dacl:
            aces = list(dacl["Data"])
    return owner, aces


def ace_dict(ace):
    """impacket ACE structure -> flat dict with sid/mask/type/guids.
    NOTE: inner["Mask"] is an ACCESS_MASK structure; ObjectType/InheritedObjectType
    are raw bytes (only present on *_OBJECT_ACE variants: types 5,6,11,12,15)."""
    out = {"type": ace["AceType"], "flags": ace["AceFlags"], "raw": ace}
    inner = ace["Ace"]
    out["mask"] = inner["Mask"]["Mask"] if hasattr(inner["Mask"], "__getitem__") else inner["Mask"]
    out["sid"] = inner["Sid"].formatCanonical() if hasattr(inner["Sid"], "formatCanonical") else None
    ot = None; iot = None
    if ace["AceType"] in (5, 6, 11, 12, 15):
        try:
            if inner["Flags"] & 1:
                ot = bin2guid(inner["ObjectType"])
        except Exception:
            pass
        try:
            if inner["Flags"] & 2:
                iot = bin2guid(inner["InheritedObjectType"])
        except Exception:
            pass
    out["object_type"] = ot
    out["inherited_type"] = iot
    return out


def evaluate_ace(a, my_sids, obj_class, trustee_name):
    """One ACE -> list of (severity, finding, why) tuples applying to me."""
    findings = []
    mask = expand_generic(a["mask"])
    # access-denied ACEs: report inverse effect but never as wins
    if a["type"] in (1, 6, 10, 12):
        return findings  # deny ACEs: skip (we don't model deny precedence)

    wp = mask & RIGHT["WriteProp"]
    gw = mask & RIGHT["GenericWrite"] or (mask & RIGHT["GenericAll"] == RIGHT["GenericAll"])
    ctrl = mask & RIGHT["ControlAccess"]
    wd = mask & RIGHT["WriteDacl"]
    wo = mask & RIGHT["WriteOwner"]
    self_r = mask & RIGHT["Self"]

    ot = a["object_type"]
    iot = a["inherited_type"]

    # ---- object-scoped rights
    if ot:
        if ot in PROP_GUIDS and (wp or gw):
            label, why = PROP_GUIDS[ot]
            sev = "HIGH" if label in ("msDS-KeyCredentialLink", "servicePrincipalName",
                                      "Members property set", "Member",
                                      "gMSA managed password") else "MED"
            findings.append((sev, f"Write {label}", why))
        elif ot in EXT_RIGHTS and (ctrl or gw):
            label, why = EXT_RIGHTS[ot]
            sev = "HIGH" if ("DCSync" in why or "Force-Change" in why) else "LOW"
            findings.append((sev, f"Ext-right {label}", why))
    # ---- unscoped rights
    if wd:
        findings.append(("HIGH", "WriteDACL", "rewrite ACL to grant yourself anything"))
    if wo:
        findings.append(("HIGH", "WriteOwner", "take ownership -> implicit WriteDacl"))
    if (mask & RIGHT["GenericAll"] == RIGHT["GenericAll"]):
        findings.append(("HIGH", "GenericAll", "full control"))
    if gw and not ot and obj_class == "group":
        findings.append(("HIGH", "GenericWrite on group", "add yourself to the group"))
    if gw and not ot and obj_class in ("user", "computer"):
        findings.append(("HIGH", "GenericWrite on " + obj_class, "write any property incl. SPN/KCL/UAC"))
    if self_r:
        findings.append(("MED", "Self (validated write)", "e.g. add-self-to-group on membership"))
    return findings


# ---------------------------------------------------------------- main flow

def dns2dn(domain):
    return ",".join(f"DC={x}" for x in domain.split("."))


def main():
    ap = argparse.ArgumentParser(description="adacl-audit - what can MY principal do via AD ACLs?")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("-u", "--username", required=True)
    ap.add_argument("-p", "--password", default="")
    ap.add_argument("-H", "--hashes", help="LM:NT")
    ap.add_argument("--dc-ip", required=True)
    ap.add_argument("--use-ldap", action="store_true")
    ap.add_argument("--lootdir", help="ntlmrelayx loot dir (users/groups/computers JSONs)")
    ap.add_argument("--group-sids", help="comma-separated extra SIDs you hold")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    use_color = sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
    RED = "\033[91m\033[1m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    DIM = "\033[2m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    if args.hashes:
        lm, nt = args.hashes.split(":") if ":" in args.hashes else ("", args.hashes)
    else:
        lm, nt = "", ""

    # loot enrichment
    sid_by_name, name_by_sid = ({}, {})
    if args.lootdir:
        sid_by_name, name_by_sid = load_loot(args.lootdir)
        print(f"[*] Loot: {len(sid_by_name)} principals loaded for offline name enrichment")

    print(f"[*] Connecting to {'LDAP' if args.use_ldap else 'LDAPS'} on {args.dc_ip}")
    try:
        from impacket.ldap import ldap as impacket_ldap
    except ImportError as e:
        print(f"[!] {e}"); sys.exit(1)
    dn = dns2dn(args.domain)
    conn = None
    for scheme in (("ldaps", "ldap") if not args.use_ldap else ("ldap",)):
        try:
            conn = impacket_ldap.LDAPConnection(f"{scheme}://{args.dc_ip}", dn, args.dc_ip)
            conn.login(args.username, args.password, args.domain, lm, nt)
            break
        except Exception as e:
            print(f"[-] {scheme.upper()} connect failed: {e}")
            conn = None
    if conn is None:
        print("[!] All LDAP connection attempts failed")
        sys.exit(1)

    # ---- resolve who I am: SID + tokenGroups
    print("[*] Resolving your identity and group SIDs")
    my_sids = set()
    my_name = args.username
    try:
        results = conn.search(searchBase=dn,
                               searchFilter=f"(sAMAccountName={args.username})",
                               attributes=["objectSid", "tokenGroups"])
        for r in results:
            if "attributes" not in r:
                continue
            for key, vals in r["attributes"]:
                if key == "objectSid" and vals:
                    s = bin2sidstr(vals[0])
                    if s: my_sids.add(s)
                elif key == "tokenGroups":
                    for tg in vals:
                        s2 = bin2sidstr(tg)
                        if s2: my_sids.add(s2)
    except Exception as e:
        print(f"[-] tokenGroups pull failed: {e}")
    if not my_sids:
        print("[!] Could not resolve your SID — aborting")
        sys.exit(1)
    if args.group_sids:
        my_sids.update(x.strip() for x in args.group_sids.split(",") if x.strip())
    # builtins every domain principal holds
    my_sids.add("S-1-1-0")   # Everyone
    my_sids.add("S-1-5-11")  # Authenticated Users
    print(f"[*] You are {my_name} ({len(my_sids)} effective SIDs incl. Everyone/AU)")

    # ---- fetch target object set
    print("[*] Enumerating objects with nTSecurityDescriptor (this is the heavy pull)")
    targets = []
    for label, filt in [("users", "(&(objectClass=user)(!(objectClass=computer)))"),
                        ("computers", "(objectClass=computer)"),
                        ("groups", "(objectClass=group)")]:
        try:
            results = conn.search(searchBase=dn, searchFilter=filt,
                                  attributes=["nTSecurityDescriptor", "sAMAccountName", "objectClass"])
            for r in results:
                if "attributes" not in r:
                    continue
                attrs = {}
                for key, vals in r["attributes"]:
                    attrs[key] = vals
                sd_raw = attrs.get("nTSecurityDescriptor", [None])
                sd_raw = sd_raw[0] if sd_raw else None
                name = attrs.get("sAMAccountName", [""])
                name = name[0] if name else ""
                objclass = attrs.get("objectClass", [""])
                objclass = objclass[-1] if objclass else ""
                targets.append({"label": label, "dn": str(r["objectName"]),
                                "name": name, "class": objclass, "sd": sd_raw})
        except Exception as e:
            print(f"[-] {label} pull failed: {e}")
    print(f"[*] Pulled SDs for {len(targets)} objects")

    # ---- parse and evaluate
    results = []
    for t in targets:
        if not t["sd"]:
            continue
        owner, aces = parse_sd(t["sd"])
        for ace in aces:
            a = ace_dict(ace)
            if a["sid"] not in my_sids:
                continue
            trustee = name_by_sid.get(a["sid"], a["sid"])
            findings = evaluate_ace(a, my_sids, t["class"], trustee)
            for sev, what, why in findings:
                results.append({"obj": t["name"] or t["dn"], "obj_class": t["class"],
                                "sev": sev, "right": what, "why": why,
                                "trustee": trustee, "via": a["sid"]})

    # ---- report
    high = [r for r in results if r["sev"] == "HIGH"]
    med = [r for r in results if r["sev"] == "MED"]
    low = [r for r in results if r["sev"] == "LOW"]

    print()
    if not results:
        print("[*] No dangerous ACL rights found for your principal. Clean sweep.")
        sys.exit(0)

    if high:
        print(f"{RED}>>> HIGH-WIN: {len(high)} dangerous right(s){RESET}")
        for r in high:
            via = f" via {r['trustee']}" if r['trustee'] != my_name else ""
            print(f"{RED}  [!] {r['right']} on {r['obj']} ({r['obj_class']}){via}{RESET}")
            print(f"{RED}      why: {r['why']}{RESET}")
    if med:
        print(f"{BOLD}>>> MEDIUM: {len(med)} notable right(s){RESET}")
        for r in med:
            print(f"  [-] {r['right']} on {r['obj']} ({r['obj_class']}) — {r['why']}")
    if low:
        print(f"{DIM}>>> LOW: {len(low)} info right(s){RESET}")
        for r in low:
            print(f"  {DIM}[i] {r['right']} on {r['obj']} — {r['why']}{RESET}")

    print()
    print(f"{BOLD}=== Next steps (keyed to findings){RESET}")
    for i, r in enumerate(high + med, 1):
        right, obj, why = r["right"], r["obj"], r["why"]
        if "msDS-KeyCredentialLink" in right:
            print(f"  {i}. Shadow credentials on {obj}: pywhisker -d {args.domain} --dc-ip {args.dc_ip} "
                  f"-u {args.username} -p <pass> --target {obj} --action add")
        elif "SPN" in right:
            print(f"  {i}. Targeted Kerberoast {obj}: set SPN then GetUserSPNs.py / hashcat")
        elif "group membership" in right.lower() or right.startswith("GenericWrite on group"):
            print(f"  {i}. Add yourself to {obj}: net group / rbcd / PowerView Add-GroupMember")
        elif "WriteDACL" in right or "WriteOwner" in right:
            print(f"  {i}. Rewrite {obj}'s ACL: PowerView Set-DomainObjectACL / Set-DomainOwner")
        elif "DCSync" in why:
            print(f"  {i}. DCSync {obj}: secretsdump.py -just-dc <user>@<domain> (needs both Get-Changes + All)")
        elif "Force-Change" in why:
            print(f"  {i}. Reset {obj}'s password: set via LDAPS or rpc (PowerView Set-DomainUserPassword)")
        else:
            print(f"  {i}. {right} on {obj}: {why}")
    sys.exit(0)


if __name__ == "__main__":
    main()