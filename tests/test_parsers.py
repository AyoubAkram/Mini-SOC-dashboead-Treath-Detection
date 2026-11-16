"""Parser tests on real-format log lines for all 8 sources."""

import json
from datetime import datetime, timezone

import pytest

from backend import parsers, utils
from backend.models import EventType, LogSource


# -- Linux auth.log ----------------------------------------------------------

def test_auth_failed_password_invalid_user():
    line = "Jun 14 15:16:01 bastion sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 52413 ssh2"
    e = parsers.parse_linux_auth(line)
    assert e.event_type == EventType.LOGIN_FAILED
    assert (e.username, e.source_ip, e.source_port) == ("admin", "203.0.113.7", 52413)
    assert (e.host, e.process, e.log_source) == ("bastion", "sshd", LogSource.LINUX_AUTH)
    assert e.extra["invalid_user"] is True and e.extra["pid"] == 1234
    assert (e.timestamp.month, e.timestamp.day, e.timestamp.hour) == (6, 14, 15)
    assert e.raw == line


def test_auth_single_digit_day_and_iso_timestamp():
    e = parsers.parse_linux_auth("Jun  4 03:02:01 web-01 sshd[99]: Failed password for root from 10.0.0.9 port 22 ssh2")
    assert e.timestamp.day == 4 and e.username == "root" and e.extra["invalid_user"] is False
    e = parsers.parse_linux_auth("2026-06-14T15:16:01.123456+02:00 web-01 sshd[99]: Accepted publickey for alice from 10.0.0.9 port 4022 ssh2: ED25519 SHA256:abc")
    assert e.event_type == EventType.LOGIN_SUCCESS
    assert e.timestamp == datetime(2026, 6, 14, 13, 16, 1, 123456, tzinfo=timezone.utc)
    assert e.extra["auth_method"] == "publickey"


@pytest.mark.parametrize("msg,event_type,user", [
    ("sshd[1]: Invalid user oracle from 198.51.100.4 port 4444", EventType.INVALID_USER, "oracle"),
    ("sshd[1]: pam_unix(sshd:session): session opened for user bob(uid=1000) by (uid=0)", EventType.SESSION_OPENED, "bob"),
    ("sshd[1]: pam_unix(sshd:session): session closed for user bob", EventType.SESSION_CLOSED, "bob"),
    ("sudo[1]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", EventType.SUDO_COMMAND, "alice"),
    ("sudo[1]:   bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash", EventType.SUDO_FAILED, "bob"),
    ("sudo[1]:   eve : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/su", EventType.SUDO_FAILED, "eve"),
    ("sudo[1]: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=bob", EventType.SUDO_FAILED, "bob"),
    ("su[1]: pam_unix(su:auth): authentication failure; logname=bob uid=1000 euid=0 tty=pts/1 ruser=bob rhost=  user=root", EventType.LOGIN_FAILED, "root"),
    ("useradd[1]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash", EventType.ACCOUNT_CREATED, "backdoor"),
])
def test_auth_event_types(msg, event_type, user):
    e = parsers.parse_linux_auth(f"Jun 14 15:16:01 host {msg}")
    assert e.event_type == event_type
    assert e.username == user


def test_auth_sudo_details_and_pam_sshd_not_double_counted():
    e = parsers.parse_linux_auth("Jun 14 15:16:01 h sudo:   bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    assert e.extra["command"] == "/bin/cat /etc/shadow" and e.extra["target_user"] == "root"
    # sshd logs its own 'Failed password' line for the same attempt
    e = parsers.parse_linux_auth("Jun 14 15:16:01 h sshd[7]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root")
    assert e.event_type == EventType.UNKNOWN
    assert (e.username, e.source_ip) == ("root", "203.0.113.7")


def test_auth_unrecognised_message_keeps_ip_and_garbage_is_none():
    e = parsers.parse_linux_auth("Jun 14 15:16:01 h sshd[7]: Connection closed by authenticating user root 203.0.113.7 port 1 [preauth]")
    assert e is not None and e.event_type == EventType.UNKNOWN
    e = parsers.parse_linux_auth("Jun 14 15:16:01 h sshd[7]: Received disconnect from 203.0.113.7 port 51234:11: Bye")
    assert e.source_ip == "203.0.113.7" and e.source_port == 51234
    assert parsers.parse_linux_auth("not a log line") is None
    assert parsers.parse_linux_auth("") is None


# -- Windows -----------------------------------------------------------------

def win(event_id, **fields):
    return json.dumps({"EventID": event_id, "TimeCreated": "2026-06-14T15:16:01.5Z",
                       "Computer": "WIN-DC01.corp.local", **fields})


@pytest.mark.parametrize("event_id,event_type", [
    (4625, EventType.LOGIN_FAILED), (4624, EventType.LOGIN_SUCCESS),
    (4672, EventType.PRIVILEGE_ASSIGNED), (4720, EventType.ACCOUNT_CREATED),
    (4740, EventType.ACCOUNT_LOCKED), (4648, EventType.EXPLICIT_CREDENTIAL_LOGON),
    (4688, EventType.UNKNOWN),
])
def test_windows_event_ids(event_id, event_type):
    e = parsers.parse_windows_event(win(event_id, TargetUserName="dave", SubjectUserName="admin"))
    assert e.event_type == event_type and e.extra["event_id"] == event_id


def test_windows_fields():
    e = parsers.parse_windows_event(win(4625, TargetUserName="dave", IpAddress="::ffff:203.0.113.9",
                                        IpPort="50123", LogonType=3, SubjectUserName="-"))
    assert (e.username, e.source_ip, e.source_port) == ("dave", "203.0.113.9", 50123)
    assert e.host == "WIN-DC01.corp.local" and e.extra["logon_type"] == 3
    assert e.timestamp == datetime(2026, 6, 14, 15, 16, 1, 500000, tzinfo=timezone.utc)
    # account creation: the new account is the user, the creator is kept in extra
    e = parsers.parse_windows_event(win(4720, TargetUserName="helpdesk2", SubjectUserName="dave"))
    assert e.username == "helpdesk2" and e.extra["subject_user"] == "dave"
    # privilege / explicit credentials: the acting account is the user
    e = parsers.parse_windows_event(win(4648, TargetUserName="Administrator", SubjectUserName="bob", IpAddress="-"))
    assert e.username == "bob" and e.extra["target_user"] == "Administrator" and e.source_ip is None


def test_windows_winlogbeat_and_dotnet_date():
    line = json.dumps({"@timestamp": "2026-06-14T15:16:01.000Z", "winlog": {
        "event_id": "4625", "computer_name": "WS1", "event_data": {"TargetUserName": "erin", "IpAddress": "10.0.0.5"}}})
    e = parsers.parse_windows_event(line)
    assert (e.event_type, e.username, e.host) == (EventType.LOGIN_FAILED, "erin", "WS1")
    e = parsers.parse_windows_event(json.dumps({"Id": 4624, "TimeCreated": "/Date(1781450161000)/", "MachineName": "WS1"}))
    assert e.timestamp == datetime.fromtimestamp(1781450161, tz=timezone.utc)
    assert parsers.parse_windows_event("{bad json") is None
    assert parsers.parse_windows_event('{"no": "event id"}') is None
    assert parsers.parse_windows_event('[1, 2]') is None


# -- Firewall ----------------------------------------------------------------

def test_firewall_iptables_drop():
    line = ("Jun 14 15:16:01 fw-01 kernel: [12345.678901] IPTABLES-DROP: IN=eth0 OUT= MAC=00:16:3e:5e:6c:00 "
            "SRC=203.0.113.7 DST=10.0.1.10 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=1 DF PROTO=TCP SPT=41000 DPT=22 "
            "WINDOW=1024 RES=0x00 SYN URGP=0")
    e = parsers.parse_firewall(line)
    assert e.event_type == EventType.FIREWALL_DROP
    assert (e.source_ip, e.dest_ip, e.source_port, e.dest_port, e.protocol) == ("203.0.113.7", "10.0.1.10", 41000, 22, "tcp")
    assert e.extra["tcp_flags"] == ["SYN"] and e.extra["in_interface"] == "eth0" and e.extra["out_interface"] is None
    assert e.extra["prefix"] == "IPTABLES-DROP" and e.extra["ttl"] == 52


def test_firewall_ufw_udp_and_unknown_prefix():
    e = parsers.parse_firewall("Jun 14 15:16:01 h kernel: [1.0] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.1 DST=10.0.0.1 LEN=60 PROTO=UDP SPT=53 DPT=5353 LEN=40")
    assert e.event_type == EventType.FIREWALL_DROP and e.protocol == "udp" and e.extra["tcp_flags"] == []
    e = parsers.parse_firewall("Jun 14 15:16:01 h kernel: [UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.1 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=443 ACK PSH")
    assert e.event_type == EventType.FIREWALL_ACCEPT and e.extra["tcp_flags"] == ["ACK", "PSH"]
    e = parsers.parse_firewall("Jun 14 15:16:01 h kernel: IN=eth0 OUT= SRC=198.51.100.1 DST=10.0.0.1 PROTO=ICMP TYPE=8")
    assert e.event_type == EventType.UNKNOWN and e.dest_port is None
    assert parsers.parse_firewall("Jun 14 15:16:01 h kernel: usb 1-1: new device") is None


# -- IDS ---------------------------------------------------------------------

def test_ids_snort_fast():
    line = ("06/14-15:16:01.123456  [**] [1:2010935:3] ET SCAN Suspicious inbound to MSSQL port 1433 [**] "
            "[Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 203.0.113.7:5555 -> 10.0.0.5:1433")
    e = parsers.parse_ids(line)
    assert e.event_type == EventType.IDS_ALERT and e.message == "ET SCAN Suspicious inbound to MSSQL port 1433"
    assert (e.source_ip, e.source_port, e.dest_ip, e.dest_port, e.protocol) == ("203.0.113.7", 5555, "10.0.0.5", 1433, "tcp")
    assert e.extra["signature_id"] == 2010935 and e.extra["priority"] == 2
    assert (e.timestamp.month, e.timestamp.day, e.timestamp.second) == (6, 14, 1)


def test_ids_snort_icmp_year_and_no_classification():
    e = parsers.parse_ids("06/14/25-15:16:01.000001 [**] [1:366:7] ICMP PING *NIX [**] [Priority: 3] {ICMP} 10.0.0.9 -> 10.0.0.1")
    assert e.timestamp.year == 2025 and e.source_ip == "10.0.0.9" and e.source_port is None
    assert e.extra["classification"] is None
    assert parsers.parse_ids("random text") is None


def test_ids_suricata_eve():
    line = json.dumps({"timestamp": "2026-06-14T15:16:01.123456+0000", "event_type": "alert",
                       "src_ip": "203.0.113.7", "src_port": 4444, "dest_ip": "10.0.0.5", "dest_port": 80, "proto": "TCP",
                       "alert": {"signature_id": 2006446, "signature": "ET WEB_SERVER SQLi", "category": "Web Application Attack", "severity": 1}})
    e = parsers.parse_ids(line)
    assert e.event_type == EventType.IDS_ALERT and e.message == "ET WEB_SERVER SQLi"
    assert e.dest_port == 80 and e.extra["signature_id"] == 2006446
    assert e.timestamp == datetime(2026, 6, 14, 15, 16, 1, 123456, tzinfo=timezone.utc)
    flow = parsers.parse_ids(json.dumps({"timestamp": "2026-06-14T15:16:01+00:00", "event_type": "flow", "src_ip": "10.0.0.1"}))
    assert flow.event_type == EventType.UNKNOWN and flow.extra["eve_type"] == "flow"


# -- Web ---------------------------------------------------------------------

def test_web_combined():
    line = ('203.0.113.7 - frank [14/Jun/2026:15:16:01 +0200] "GET /products?id=1%20UNION%20SELECT HTTP/1.1" 500 1234 '
            '"https://example.com/" "sqlmap/1.8"')
    e = parsers.parse_web(line)
    assert e.event_type == EventType.HTTP_REQUEST and e.source_ip == "203.0.113.7" and e.username == "frank"
    assert e.timestamp == datetime(2026, 6, 14, 13, 16, 1, tzinfo=timezone.utc)
    assert e.extra == {"method": "GET", "path": "/products?id=1%20UNION%20SELECT", "http_version": "HTTP/1.1",
                       "status": 500, "bytes": 1234, "referrer": "https://example.com/", "user_agent": "sqlmap/1.8"}


def test_web_common_format_malformed_request_and_escaped_quotes():
    e = parsers.parse_web('10.0.0.1 - - [14/Jun/2026:15:16:01 +0000] "GET / HTTP/1.0" 304 -')
    assert e.extra["bytes"] == 0 and e.extra["user_agent"] is None and e.username is None
    e = parsers.parse_web('10.0.0.1 - - [14/Jun/2026:15:16:01 +0000] "\\x16\\x03\\x01" 400 166 "-" "-"')
    assert e.extra["method"] is None and e.extra["status"] == 400
    e = parsers.parse_web('10.0.0.1 - - [14/Jun/2026:15:16:01 +0000] "GET /a HTTP/1.1" 200 5 "-" "evil \\" agent"')
    assert e.extra["user_agent"] == 'evil \\" agent'
    e = parsers.parse_web('2001:db8::1 - - [14/Jun/2026:15:16:01 +0000] "GET / HTTP/2.0" 200 5 "-" "x"')
    assert e.source_ip == "2001:db8::1"
    assert parsers.parse_web("nonsense") is None


# -- CloudTrail --------------------------------------------------------------

def trail(name, **over):
    record = {"eventTime": "2026-06-14T15:16:01Z", "eventSource": "iam.amazonaws.com", "eventName": name,
              "awsRegion": "eu-west-3", "sourceIPAddress": "203.0.113.7",
              "userIdentity": {"type": "IAMUser", "userName": "carol"}}
    record.update(over)
    return json.dumps(record)


def test_cloudtrail_event_mapping():
    e = parsers.parse_cloudtrail(trail("ConsoleLogin", responseElements={"ConsoleLogin": "Failure"}))
    assert (e.event_type, e.username, e.source_ip) == (EventType.LOGIN_FAILED, "carol", "203.0.113.7")
    assert parsers.parse_cloudtrail(trail("ConsoleLogin", responseElements={"ConsoleLogin": "Success"})).event_type == EventType.LOGIN_SUCCESS
    e = parsers.parse_cloudtrail(trail("CreateUser", requestParameters={"userName": "backdoor"}))
    assert e.event_type == EventType.ACCOUNT_CREATED and e.extra["target_user"] == "backdoor"
    assert parsers.parse_cloudtrail(trail("AttachUserPolicy")).event_type == EventType.PRIVILEGE_ASSIGNED
    e = parsers.parse_cloudtrail(trail("GetObject", errorCode="AccessDenied", eventSource="s3.amazonaws.com"))
    assert e.event_type == EventType.CLOUD_API_CALL and e.message == "s3.amazonaws.com:GetObject (AccessDenied)"


def test_cloudtrail_identity_fallbacks_and_service_source():
    e = parsers.parse_cloudtrail(trail("AssumeRole", userIdentity={"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/Admin/session1"}))
    assert e.username == "session1"
    e = parsers.parse_cloudtrail(trail("ConsoleLogin", userIdentity={"type": "Root"}, sourceIPAddress="cloudformation.amazonaws.com"))
    assert e.username == "Root" and e.source_ip is None
    assert parsers.parse_cloudtrail('{"eventName": "x"}') is None


# -- Zeek --------------------------------------------------------------------

def test_zeek_json_conn_dns_http():
    e = parsers.parse_zeek(json.dumps({"ts": 1781450161.5, "uid": "C1", "id.orig_h": "10.0.0.5", "id.orig_p": 50000,
                                       "id.resp_h": "203.0.113.7", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                                       "duration": 1.5, "orig_bytes": 900000000, "resp_bytes": 100, "conn_state": "SF"}))
    assert e.event_type == EventType.NETWORK_CONNECTION
    assert (e.source_ip, e.dest_ip, e.dest_port) == ("10.0.0.5", "203.0.113.7", 443)
    assert e.extra["orig_bytes"] == 900000000 and e.extra["duration"] == 1.5
    assert e.timestamp == datetime.fromtimestamp(1781450161.5, tz=timezone.utc)
    e = parsers.parse_zeek(json.dumps({"ts": "2026-06-14T15:16:01.000000Z", "id.orig_h": "10.0.0.5", "id.orig_p": 1,
                                       "id.resp_h": "10.0.0.2", "id.resp_p": 53, "proto": "udp",
                                       "query": "aabbcc.evil.example", "qtype_name": "TXT"}))
    assert e.event_type == EventType.DNS_QUERY and e.extra["query"] == "aabbcc.evil.example"
    e = parsers.parse_zeek(json.dumps({"ts": 1.0, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", "id.resp_p": 80,
                                       "method": "GET", "host": "x.test", "uri": "/a", "status_code": 404}))
    assert e.event_type == EventType.HTTP_REQUEST and e.extra["status"] == 404


def test_zeek_tsv_with_fields_header():
    assert parsers.parse_zeek("#separator \\x09") is None
    assert parsers.parse_zeek("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name") is None
    e = parsers.parse_zeek("1781450161.123456\tCabc\t10.0.0.5\t40000\t10.0.0.2\t53\tudp\texample.com\tA")
    assert e.event_type == EventType.DNS_QUERY and e.source_port == 40000
    assert parsers.parse_zeek("1781450161.1\tCabc\t10.0.0.5") is None  # wrong column count
    # back to conn.log columns, with '-' for unset values
    assert parsers.parse_zeek("#fields\t" + "\t".join(parsers.ZEEK_CONN_FIELDS)) is None
    row = ["1781450161.1", "Cx", "10.0.0.5", "40000", "203.0.113.7", "22", "tcp", "-", "-", "-", "-", "S0",
           "-", "-", "0", "S", "1", "44", "0", "0", "(empty)"]
    e = parsers.parse_zeek("\t".join(row))
    assert e.event_type == EventType.NETWORK_CONNECTION
    assert e.extra["conn_state"] == "S0" and e.extra["orig_bytes"] is None and e.extra["service"] is None


# -- Syslog ------------------------------------------------------------------

def test_syslog_rfc5424():
    e = parsers.parse_syslog("<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su 1234 ID47 - ﻿'su root' failed for lonvick on /dev/pts/8")
    assert e.log_source == LogSource.SYSLOG and e.event_type == EventType.SYSLOG_MESSAGE
    assert (e.host, e.process) == ("mymachine.example.com", "su")
    assert e.message == "'su root' failed for lonvick on /dev/pts/8"
    assert e.extra["facility"] == "auth" and e.extra["severity"] == "crit"
    assert e.extra["msgid"] == "ID47" and e.extra["pid"] == 1234 and e.extra["format"] == "rfc5424"
    assert e.timestamp == datetime(2003, 10, 11, 22, 14, 15, 3000, tzinfo=timezone.utc)


def test_syslog_structured_data_and_nil_values():
    e = parsers.parse_syslog('<165>1 2026-06-14T15:16:01-07:00 host app - - [exampleSDID@32473 iut="3" eventSource="App \\] x"][other@1 a="b"] An event')
    assert e.message == "An event" and e.extra["structured_data"].startswith("[exampleSDID@32473")
    assert e.extra["facility"] == "local4" and e.extra["severity"] == "notice" and "pid" not in e.extra
    assert e.timestamp.hour == 22
    e = parsers.parse_syslog("<13>1 2026-06-14T15:16:01Z - - - - -")
    assert e.host is None and e.process is None and e.message == ""


def test_syslog_auth_daemons_keep_their_meaning_and_rfc3164_fallback():
    e = parsers.parse_syslog("<38>1 2026-06-14T15:16:01Z bastion sshd 4321 - - Failed password for root from 203.0.113.7 port 22 ssh2")
    assert e.log_source == LogSource.SYSLOG and e.event_type == EventType.LOGIN_FAILED
    assert (e.username, e.source_ip) == ("root", "203.0.113.7") and e.extra["facility"] == "auth"
    e = parsers.parse_syslog("<30>Jun 14 15:16:01 web-01 cron[77]: (root) CMD (run-parts /etc/cron.hourly)")
    assert e.event_type == EventType.SYSLOG_MESSAGE and e.extra["format"] == "rfc3164"
    assert e.process == "cron" and e.extra["facility"] == "daemon" and e.extra["pid"] == 77
    e = parsers.parse_syslog("Jun 14 15:16:01 web-01 systemd[1]: Started Session 3 of user bob.")
    assert e.process == "systemd" and "facility" not in e.extra
    assert parsers.parse_syslog("hello") is None


# -- journald ----------------------------------------------------------------

def test_journald():
    line = json.dumps({"__REALTIME_TIMESTAMP": "1781450161000000", "_HOSTNAME": "kali", "SYSLOG_IDENTIFIER": "sshd",
                       "_PID": "42", "_SYSTEMD_UNIT": "ssh.service", "PRIORITY": "6",
                       "MESSAGE": "Failed password for casper from 127.0.0.1 port 40000 ssh2"})
    e = parsers.parse_journald(line)
    assert e.log_source == LogSource.LINUX_AUTH and e.event_type == EventType.LOGIN_FAILED
    assert (e.username, e.source_ip, e.host) == ("casper", "127.0.0.1", "kali")
    assert e.extra["unit"] == "ssh.service" and e.extra["severity"] == "info"
    assert e.timestamp == datetime.fromtimestamp(1781450161, tz=timezone.utc)
    e = parsers.parse_journald(json.dumps({"_COMM": "NetworkManager", "MESSAGE": [104, 105]}))
    assert e.log_source == LogSource.SYSLOG and e.message == "hi" and e.event_type == EventType.SYSLOG_MESSAGE
    assert parsers.parse_journald("not json") is None


# -- registry / helpers -------------------------------------------------------

def test_registry_covers_all_sources_and_never_raises_on_garbage():
    assert set(parsers.PARSERS) == set(LogSource)
    garbage = ["", "   ", "{}", "[]", "null", "{\"a\":", "\x00\x01", "<999>1 x", "a\tb\tc\td\te\tf\tg", "🔥" * 50,
               '{"EventID": "abc", "TimeCreated": "x"}', '{"eventName": 1, "eventTime": 5}', '{"ts": "x", "id.orig_h": "1"}',
               '{"timestamp": "nope", "event_type": "alert"}', "99/99-99:99:99.1 [**] [1:1:1] x [**] {TCP} a -> b",
               '1.1.1.1 - - [99/Zzz/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1']
    for source in LogSource:
        for line in garbage:
            assert parsers.parse_line(source, line) is None, (source, line)


def test_split_records():
    wrapped = json.dumps({"Records": [{"eventName": "A"}, {"eventName": "B"}]})
    records = parsers.split_records("cloudtrail", wrapped)
    assert [json.loads(r)["eventName"] for r in records] == ["A", "B"]
    assert len(parsers.split_records("windows_event", '[{"EventID": 1}, {"EventID": 2}]')) == 2
    assert parsers.split_records("cloudtrail", '{"eventName":"A"}\n{"eventName":"B"}\n') == ['{"eventName":"A"}', '{"eventName":"B"}']
    assert parsers.split_records("web", "a\nb\n") == ["a", "b"]


# -- utils -------------------------------------------------------------------

def test_bsd_timestamp_year_rollover():
    now = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)
    assert utils.parse_bsd_timestamp("Dec 31 23:59:59", now).year == 2025
    assert utils.parse_bsd_timestamp("Jan  2 11:00:00", now).year == 2026
    assert utils.parse_bsd_timestamp("Feb 29 10:00:00", now).year == 2024  # 2026 has no Feb 29


def test_sha256_batch_is_order_and_boundary_sensitive():
    assert utils.sha256_batch(["a", "b"]) == utils.sha256_batch(["a", "b"])
    assert utils.sha256_batch(["a", "b"]) != utils.sha256_batch(["b", "a"])
    assert utils.sha256_batch(["ab", "c"]) != utils.sha256_batch(["a", "bc"])
    assert len(utils.sha256_batch([])) == 64


def test_clean_ip():
    assert utils.clean_ip("::ffff:10.0.0.1") == "10.0.0.1"
    assert utils.clean_ip("-") is None and utils.clean_ip("") is None and utils.clean_ip("example.com") is None
    assert utils.is_private_ip("10.0.0.1") and not utils.is_private_ip("8.8.8.8") and not utils.is_private_ip(None)
