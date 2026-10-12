#!/usr/bin/env python3
"""Unit tests for adenum.py pure functions - interval normalization, UAC
decoding, policy analysis, kerberoastable extraction. No network needed."""
import importlib.util
import sys

spec = importlib.util.spec_from_file_location('adenum', 'adenum.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

fails = 0

def check(cond, msg):
    global fails
    if cond:
        print('  [ok] ' + msg)
    else:
        fails += 1
        print('  [FAIL] ' + msg)


print('== interval_seconds: raw filetime (old ldap3) ==')
check(m.interval_seconds('-864000000000') == 86400, '"-864000000000" -> 86400 (1 day)')
check(m.interval_seconds('-18000000000') == 1800, '"-18000000000" -> 1800 (30 min)')
check(m.interval_seconds(864000000000) == 86400, 'int 864000000000 -> 86400')
check(m.interval_seconds(-9223372036854775808) is None, 'INT64-min sentinel -> None (never)')
check(m.interval_seconds('-9223372036854775808') is None, 'str INT64-min -> None')

print('== interval_seconds: str(timedelta) (ldap3 >= 2.6) ==')
check(m.interval_seconds('1 day, 0:00:00') == 86400, '"1 day, 0:00:00" -> 86400')
check(m.interval_seconds('0:30:00') == 1800, '"0:30:00" -> 1800')
check(m.interval_seconds('30 minutes') is None, 'garbage string -> None (no crash)')
check(m.interval_seconds('999999999 days, 23:59:59.999999') is None, 'timedelta.max -> None (never)')
check(m.interval_seconds('2 days, 3:00:00') == 183600, '"2 days, 3:00:00" -> 183600')
check(m.interval_seconds('-1 day, 0:00:00') == 86400, 'negative timedelta -> abs')

print('== interval_seconds: edge ==')
check(m.interval_seconds(None) is None, 'None -> None')
check(m.interval_seconds(0) is None, '0 -> None')
check(m.interval_seconds('0') is None, '"0" -> None')
check(m.interval_seconds('') is None, '"" -> None')

print('== human_interval ==')
check(m.human_interval(None) == 'Not Set', 'None -> Not Set')
check(m.human_interval(0) == 'None', '0 -> None')
check(m.human_interval(86400) == '1 day', '86400 -> 1 day')
check(m.human_interval(90600) == '1 day 1 hour 10 minutes', '90600 -> 1 day 1 hour 10 minutes')

print('== uac_names ==')
uac = m.uac_names(0x400000 + 0x200 + 0x20)
check('NO_PREAUTH' in uac and 'NOTREQD' in uac and 'NORMAL' in uac, '4194592 decodes 3 flags')
check(m.uac_names(None) == [], 'None -> []')
check('DISABLED' in m.uac_names(2), '2 -> DISABLED')

print('== filetime_to_dt ==')
dt = m.filetime_to_dt('132224964000000000')
check(dt is not None and dt.year == 2020, 'filetime converts to 2020 datetime')
check(m.filetime_to_dt(0) is None, '0 -> None')
check(m.filetime_to_dt(None) is None, 'None -> None')

print('== findings capture ==')
m.FINDINGS.clear()
m.finding('test', 'hello')
check(m.FINDINGS == [('test', 'hello')], 'finding() appends')

print('== p_* aliases ==')
m.p_info('alias check')

print()
if fails:
    print('FAILURES: %d' % fails)
    sys.exit(1)
print('ALL UNIT TESTS PASSED')