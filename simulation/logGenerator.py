"""
Realistic log generator
Produces raw log lines for all 8 ARGUS sources, with attack scenarios mixed
into normal background traffic. Everything is synthetic: attacker addresses
come from the RFC 5737 documentation ranges and never touch a real system.

Examples:
    python simulation/logGenerator.py --out data/generated --seed 42
    python simulation/logGenerator.py --scenarios brute_force,port_scan --ingest
    python simulation/logGenerator.py --stream --rate 20      # live, for collector/fileTail.py
    python simulation/logGenerator.py --sample data/sample_logs.json
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from faker import Faker

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SOURCES = ["linux_auth", "windows_event", "firewall", "ids", "web", "cloudtrail", "zeek", "syslog"]

# (timestamp, source, raw line)
Event = Tuple[datetime, str, str]

ATTACKER_NETS = ["203.0.113", "198.51.100", "192.0.2"]  # RFC 5737 TEST-NETs
INTERNAL_USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
COMMON_TARGETS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "deploy", "pi"]
LINUX_HOSTS = ["web-01", "web-02", "db-01", "bastion"]
WINDOWS_HOSTS = ["WIN-DC01", "WIN-FS02", "WIN-WS113"]
WEB_PATHS = ["/", "/index.html", "/login", "/products", "/products?id=12", "/cart", "/api/items",
             "/static/app.js", "/static/style.css", "/about", "/contact", "/favicon.ico"]
SQLI_PAYLOADS = [
    "/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT username,password FROM users--",
    "/login?user=admin'--&pass=x", "/products?id=1; DROP TABLE users--",
    "/search?q=' OR 1=1#", "/products?id=1' AND SLEEP(5)--",
    "/items?cat=1 UNION ALL SELECT NULL,NULL,version()--", "/products?id=-1' UNION SELECT 1,2,3--",
]
AWS_CALLS = [("s3.amazonaws.com", "GetObject"), ("s3.amazonaws.com", "ListBuckets"),
             ("ec2.amazonaws.com", "DescribeInstances"), ("sts.amazonaws.com", "GetCallerIdentity"),
             ("logs.amazonaws.com", "DescribeLogGroups"), ("iam.amazonaws.com", "ListUsers")]
DAEMONS = [("cron", "(root) CMD (run-parts /etc/cron.hourly)"),
           ("systemd", "Started Daily apt download activities."),
           ("dhclient", "DHCPACK of 10.0.1.{n} from 10.0.1.1"),
           ("kernel", "usb 1-1: new high-speed USB device number {n} using xhci_hcd"),
           ("nginx", "worker process {n} exited with code 0"),
           ("postfix/smtpd", "connect from mail.example.org[10.0.3.{n}]")]


class LogGenerator:
    def __init__(self, seed: Optional[int] = None, start: Optional[datetime] = None,
                 duration_minutes: float = 60):
        self.rng = random.Random(seed)
        self.fake = Faker()
        if seed is not None:
            self.fake.seed_instance(seed)
        self.duration = timedelta(minutes=duration_minutes)
        self.start = start or (datetime.now(timezone.utc) - self.duration)
        self.events: List[Event] = []
        self._zeek_uid = 0

    # -- helpers -----------------------------------------------------------

    def _when(self) -> datetime:
        return self.start + self.duration * self.rng.random()

    def _attack_start(self, length_seconds: float) -> datetime:
        room = max(self.duration.total_seconds() - length_seconds, 0)
        return self.start + timedelta(seconds=self.rng.uniform(0.1, 0.9) * room)

    def attacker_ip(self) -> str:
        return f"{self.rng.choice(ATTACKER_NETS)}.{self.rng.randint(2, 254)}"

    def internal_ip(self) -> str:
        return f"10.0.{self.rng.randint(1, 3)}.{self.rng.randint(10, 250)}"

    def external_ip(self) -> str:
        return self.fake.ipv4_public()

    def _port(self) -> int:
        return self.rng.randint(32768, 60999)

    def add(self, ts: datetime, source: str, line: str) -> None:
        self.events.append((ts, source, line))

    # -- raw line formatters (one per source) -------------------------------

    @staticmethod
    def _bsd(ts: datetime) -> str:
        return f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')}"

    def auth(self, ts, host, process, message) -> None:
        pid = self.rng.randint(800, 65000)
        self.add(ts, "linux_auth", f"{self._bsd(ts)} {host} {process}[{pid}]: {message}")

    def windows(self, ts, event_id: int, host: str, **fields) -> None:
        record = {"EventID": event_id, "TimeCreated": ts.isoformat().replace("+00:00", "Z"),
                  "Computer": f"{host}.corp.local", "Channel": "Security"}
        record.update(fields)
        self.add(ts, "windows_event", json.dumps(record, separators=(",", ":")))

    def firewall(self, ts, action, src, dst, dport, proto="TCP", sport=None, flags="SYN") -> None:
        prefix = "IPTABLES-DROP: " if action == "drop" else "IPTABLES-ACCEPT: "
        uptime = (ts - self.start).total_seconds() + 1000
        line = (f"{self._bsd(ts)} fw-01 kernel: [{uptime:12.6f}] {prefix}IN=eth0 OUT= "
                f"MAC=00:16:3e:5e:6c:00:00:16:3e:11:22:33:08:00 SRC={src} DST={dst} "
                f"LEN={self.rng.choice([40, 44, 52, 60])} TOS=0x00 PREC=0x00 "
                f"TTL={self.rng.choice([48, 52, 57, 64, 115])} ID={self.rng.randint(1, 65535)} DF "
                f"PROTO={proto} SPT={sport or self._port()} DPT={dport}")
        if proto == "TCP":
            line += f" WINDOW={self.rng.choice([1024, 29200, 64240])} RES=0x00 {flags} URGP=0"
        else:
            line += f" LEN={self.rng.randint(20, 120)}"
        self.add(ts, "firewall", line)

    def ids(self, ts, sid, message, classification, priority, proto, src, sport, dst, dport) -> None:
        stamp = ts.strftime("%m/%d-%H:%M:%S.") + f"{ts.microsecond:06d}"
        self.add(ts, "ids", f"{stamp}  [**] [1:{sid}:{self.rng.randint(1, 9)}] {message} [**] "
                            f"[Classification: {classification}] [Priority: {priority}] "
                            f"{{{proto}}} " + (f"{src} -> {dst}" if proto == "ICMP"
                                               else f"{src}:{sport} -> {dst}:{dport}"))

    def web(self, ts, ip, method, path, status, size, user_agent, user="-", referrer="-") -> None:
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        self.add(ts, "web", f'{ip} - {user} [{stamp}] "{method} {path} HTTP/1.1" {status} {size} '
                            f'"{referrer}" "{user_agent}"')

    def cloudtrail(self, ts, event_source, event_name, ip, user, user_agent="aws-cli/2.15.30",
                   error=None, response=None, params=None) -> None:
        record = {
            "eventVersion": "1.08",
            "userIdentity": {"type": "IAMUser", "userName": user, "accountId": "123456789012",
                             "arn": f"arn:aws:iam::123456789012:user/{user}"},
            "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": event_source,
            "eventName": event_name, "awsRegion": "eu-west-3", "sourceIPAddress": ip,
            "userAgent": user_agent, "requestParameters": params, "responseElements": response,
            "eventID": self.fake.uuid4(), "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        }
        if error:
            record["errorCode"] = error
        self.add(ts, "cloudtrail", json.dumps(record, separators=(",", ":")))

    def _uid(self) -> str:
        self._zeek_uid += 1
        return f"C{self.rng.getrandbits(48):012x}{self._zeek_uid}"

    def zeek_conn(self, ts, src, dst, dport, proto="tcp", service=None, duration=0.5,
                  orig_bytes=500, resp_bytes=2000, state="SF") -> None:
        record = {"ts": round(ts.timestamp(), 6), "uid": self._uid(), "id.orig_h": src,
                  "id.orig_p": self._port(), "id.resp_h": dst, "id.resp_p": dport, "proto": proto,
                  "duration": round(duration, 6), "orig_bytes": orig_bytes,
                  "resp_bytes": resp_bytes, "conn_state": state}
        if service:
            record["service"] = service
        self.add(ts, "zeek", json.dumps(record, separators=(",", ":")))

    def zeek_dns(self, ts, src, query, qtype="A", rcode="NOERROR", resolver="10.0.0.2") -> None:
        record = {"ts": round(ts.timestamp(), 6), "uid": self._uid(), "id.orig_h": src,
                  "id.orig_p": self._port(), "id.resp_h": resolver, "id.resp_p": 53,
                  "proto": "udp", "query": query, "qtype_name": qtype, "rcode_name": rcode}
        self.add(ts, "zeek", json.dumps(record, separators=(",", ":")))

    def syslog(self, ts, host, app, message, facility=3, severity=6) -> None:
        stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
        self.add(ts, "syslog", f"<{facility * 8 + severity}>1 {stamp} {host} {app} "
                               f"{self.rng.randint(300, 9000)} - - {message}")

    # -- normal background traffic -----------------------------------------

    def _normal_linux_auth(self) -> None:
        ts, host, user = self._when(), self.rng.choice(LINUX_HOSTS), self.rng.choice(INTERNAL_USERS)
        ip = self.internal_ip()
        kind = self.rng.random()
        if kind < 0.45:
            method = self.rng.choice(["publickey", "password"])
            self.auth(ts, host, "sshd", f"Accepted {method} for {user} from {ip} port {self._port()} ssh2")
            self.auth(ts + timedelta(milliseconds=40), host, "sshd",
                      f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")
        elif kind < 0.55:  # the occasional typo
            self.auth(ts, host, "sshd", f"Failed password for {user} from {ip} port {self._port()} ssh2")
        elif kind < 0.85:
            command = self.rng.choice(["/usr/bin/apt update", "/usr/bin/systemctl restart nginx",
                                       "/usr/bin/tail -n 50 /var/log/syslog", "/usr/bin/docker ps"])
            self.auth(ts, host, "sudo", f"{user} : TTY=pts/{self.rng.randint(0, 4)} ; "
                                        f"PWD=/home/{user} ; USER=root ; COMMAND={command}")
        else:
            self.auth(ts, host, "sshd", f"pam_unix(sshd:session): session closed for user {user}")

    def _normal_windows(self) -> None:
        ts, user = self._when(), self.rng.choice(INTERNAL_USERS)
        host = self.rng.choice(WINDOWS_HOSTS)
        common = dict(TargetUserName=user, TargetDomainName="CORP", IpAddress=self.internal_ip(),
                      IpPort=str(self._port()), WorkstationName=f"WS-{user.upper()}")
        if self.rng.random() < 0.9:
            self.windows(ts, 4624, host, LogonType=self.rng.choice([2, 3, 10]), **common)
        else:
            self.windows(ts, 4625, host, LogonType=3, Status="0xc000006d", **common)

    def _normal_firewall(self) -> None:
        ts = self._when()
        if self.rng.random() < 0.8:
            self.firewall(ts, "accept", self.external_ip(), "10.0.1.10", self.rng.choice([80, 443]))
        else:  # internet background noise
            self.firewall(ts, "drop", self.external_ip(), "10.0.1.10",
                          self.rng.choice([23, 445, 3389, 5060, 8080]))

    def _normal_ids(self) -> None:
        sid, message, classification, priority, proto, dport = self.rng.choice([
            (2100366, "GPL ICMP_INFO PING *NIX", "Misc activity", 3, "ICMP", 0),
            (2013028, "ET POLICY curl User-Agent Outbound", "Attempted Information Leak", 2, "TCP", 80),
            (2012647, "ET POLICY Dropbox.com Offsite File Backup in Use", "Potential Corporate Privacy Violation", 1, "TCP", 443),
        ])
        self.ids(self._when(), sid, message, classification, priority, proto,
                 self.internal_ip(), self._port(), self.external_ip(), dport)

    def _normal_web(self) -> None:
        path = self.rng.choice(WEB_PATHS)
        status = self.rng.choices([200, 304, 404, 302], weights=[80, 10, 6, 4])[0]
        self.web(self._when(), self.external_ip(), "POST" if path == "/login" else "GET", path,
                 status, self.rng.randint(200, 48000), self.fake.user_agent(),
                 referrer=self.rng.choice(["-", "https://shop.example.com/"]))

    def _normal_cloudtrail(self) -> None:
        source, name = self.rng.choice(AWS_CALLS)
        self.cloudtrail(self._when(), source, name, self.internal_ip().replace("10.0.", "52.47."),
                        self.rng.choice(INTERNAL_USERS))

    def _normal_zeek(self) -> None:
        ts, src = self._when(), self.internal_ip()
        if self.rng.random() < 0.4:
            self.zeek_dns(ts, src, self.fake.domain_name())
        else:
            self.zeek_conn(ts, src, self.external_ip(), self.rng.choice([80, 443, 443, 22]),
                           service=self.rng.choice(["ssl", "http"]),
                           duration=self.rng.uniform(0.05, 30),
                           orig_bytes=self.rng.randint(200, 5000),
                           resp_bytes=self.rng.randint(500, 250000))

    def _normal_syslog(self) -> None:
        app, template = self.rng.choice(DAEMONS)
        self.syslog(self._when(), self.rng.choice(LINUX_HOSTS), app,
                    template.format(n=self.rng.randint(2, 250)))

    def add_normal_traffic(self, count: int, sources: Optional[List[str]] = None) -> None:
        makers = {"linux_auth": self._normal_linux_auth, "windows_event": self._normal_windows,
                  "firewall": self._normal_firewall, "ids": self._normal_ids,
                  "web": self._normal_web, "cloudtrail": self._normal_cloudtrail,
                  "zeek": self._normal_zeek, "syslog": self._normal_syslog}
        chosen = [makers[s] for s in (sources or SOURCES)]
        for i in range(count):
            chosen[i % len(chosen)]()

    # -- attack scenarios ---------------------------------------------------

    def brute_force(self) -> Dict:
        """SSH password guessing, ending with a successful login as root."""
        ip, host, attempts = self.attacker_ip(), "bastion", self.rng.randint(30, 60)
        ts = self._attack_start(attempts * 3)
        self.ids(ts, 2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2,
                 "TCP", ip, self._port(), "10.0.1.5", 22)
        for _ in range(attempts):
            ts += timedelta(seconds=self.rng.uniform(0.5, 3))
            user = self.rng.choice(COMMON_TARGETS)
            if user in ("root", "git"):
                self.auth(ts, host, "sshd", f"Failed password for {user} from {ip} port {self._port()} ssh2")
            else:
                self.auth(ts, host, "sshd", f"Invalid user {user} from {ip} port {self._port()}")
                self.auth(ts + timedelta(milliseconds=900), host, "sshd",
                          f"Failed password for invalid user {user} from {ip} port {self._port()} ssh2")
        ts += timedelta(seconds=2)
        self.auth(ts, host, "sshd", f"Accepted password for root from {ip} port {self._port()} ssh2")
        self.auth(ts + timedelta(milliseconds=50), host, "sshd",
                  "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")
        return {"scenario": "brute_force", "source_ip": ip, "attempts": attempts}

    def port_scan(self) -> Dict:
        """One address probing many ports in a few seconds."""
        ip, target = self.attacker_ip(), "10.0.1.10"
        ports = self.rng.sample(range(1, 10000), self.rng.randint(120, 200))
        ts = self._attack_start(len(ports) * 0.2)
        self.ids(ts, 2009582, "ET SCAN NMAP -sS window 1024", "Attempted Information Leak", 2,
                 "TCP", ip, self._port(), target, ports[0])
        for port in ports:
            ts += timedelta(milliseconds=self.rng.randint(20, 200))
            self.firewall(ts, "drop", ip, target, port)
        return {"scenario": "port_scan", "source_ip": ip, "ports": len(ports)}

    def sql_injection(self) -> Dict:
        """sqlmap-style probing of a web application."""
        ip, requests = self.attacker_ip(), self.rng.randint(20, 40)
        ts = self._attack_start(requests * 2)
        for _ in range(requests):
            ts += timedelta(seconds=self.rng.uniform(0.2, 2))
            self.web(ts, ip, "GET", self.rng.choice(SQLI_PAYLOADS).replace(" ", "%20"),
                     self.rng.choice([200, 500, 500, 403]), self.rng.randint(300, 4000),
                     "sqlmap/1.8.4#stable (https://sqlmap.org)")
        self.ids(ts, 2006446, "ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT",
                 "Web Application Attack", 1, "TCP", ip, self._port(), "10.0.1.10", 80)
        return {"scenario": "sql_injection", "source_ip": ip, "requests": requests}

    def privilege_escalation(self) -> Dict:
        """A service account fails sudo, gets a root shell, then adds a backdoor account."""
        host, user, backdoor = "web-01", "www-data", "svc_backup"
        ts = self._attack_start(120)
        for _ in range(3):
            ts += timedelta(seconds=self.rng.uniform(2, 6))
            self.auth(ts, host, "sudo", "pam_unix(sudo:auth): authentication failure; logname= uid=33 "
                                        f"euid=0 tty=/dev/pts/1 ruser={user} rhost=  user={user}")
        ts += timedelta(seconds=3)
        self.auth(ts, host, "sudo", f"{user} : 3 incorrect password attempts ; TTY=pts/1 ; "
                                    "PWD=/var/www ; USER=root ; COMMAND=/bin/bash")
        ts += timedelta(seconds=40)
        self.auth(ts, host, "sudo", f"{user} : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash")
        ts += timedelta(seconds=15)
        self.auth(ts, host, "useradd", f"new user: name={backdoor}, UID=0, GID=0, home=/home/{backdoor}, "
                                       "shell=/bin/bash, from=/dev/pts/1")
        return {"scenario": "privilege_escalation", "username": user, "created_account": backdoor}

    def account_takeover(self) -> Dict:
        """Windows: password spraying, a successful logon, admin rights, then a new account."""
        ip, host, victim = self.attacker_ip(), "WIN-DC01", "dave"
        ts = self._attack_start(180)
        for user in INTERNAL_USERS * 3:
            ts += timedelta(seconds=self.rng.uniform(0.5, 4))
            self.windows(ts, 4625, host, TargetUserName=user, TargetDomainName="CORP", LogonType=3,
                         IpAddress=ip, IpPort=str(self._port()), Status="0xc000006d",
                         WorkstationName="KALI")
            if user == "erin":
                self.windows(ts + timedelta(milliseconds=200), 4740, host, TargetUserName=user,
                             TargetDomainName="KALI", SubjectUserName="WIN-DC01$")
        ts += timedelta(seconds=5)
        self.windows(ts, 4624, host, TargetUserName=victim, TargetDomainName="CORP", LogonType=3,
                     IpAddress=ip, IpPort=str(self._port()), WorkstationName="KALI")
        self.windows(ts + timedelta(milliseconds=30), 4672, host, SubjectUserName=victim,
                     SubjectDomainName="CORP",
                     PrivilegeList="SeDebugPrivilege SeBackupPrivilege SeTakeOwnershipPrivilege")
        ts += timedelta(seconds=45)
        self.windows(ts, 4720, host, TargetUserName="helpdesk2", TargetDomainName="CORP",
                     SubjectUserName=victim, SubjectDomainName="CORP")
        return {"scenario": "account_takeover", "source_ip": ip, "username": victim}

    def lateral_movement(self) -> Dict:
        """A compromised internal host logging in to several others in a short time."""
        src, user = "10.0.2.77", "bob"
        ts = self._attack_start(120)
        for host in LINUX_HOSTS:
            ts += timedelta(seconds=self.rng.uniform(5, 20))
            self.auth(ts, host, "sshd", f"Accepted password for {user} from {src} port {self._port()} ssh2")
            self.zeek_conn(ts, src, f"10.0.1.{LINUX_HOSTS.index(host) + 5}", 22, service="ssh",
                           duration=self.rng.uniform(5, 60))
        for host in WINDOWS_HOSTS:
            ts += timedelta(seconds=self.rng.uniform(5, 20))
            self.windows(ts, 4648, "WIN-WS113", SubjectUserName=user, TargetUserName="Administrator",
                         TargetServerName=host, IpAddress=src, IpPort=str(self._port()))
        return {"scenario": "lateral_movement", "source_ip": src, "username": user}

    def beaconing(self) -> Dict:
        """Malware calling home at a fixed interval with a little jitter."""
        src, c2, interval = "10.0.2.77", self.attacker_ip(), 60
        count = max(int(self.duration.total_seconds() * 0.8 // interval), 5)
        ts = self.start + timedelta(seconds=self.rng.uniform(1, 30))
        for _ in range(count):
            self.zeek_conn(ts, src, c2, 443, service="ssl", duration=self.rng.uniform(0.1, 0.4),
                           orig_bytes=self.rng.randint(180, 220), resp_bytes=self.rng.randint(90, 130))
            ts += timedelta(seconds=interval + self.rng.uniform(-2, 2))
        return {"scenario": "beaconing", "source_ip": src, "dest_ip": c2, "connections": count}

    def data_exfiltration(self) -> Dict:
        """A large outbound upload to an unknown external address."""
        src, dst = "10.0.3.40", self.attacker_ip()
        ts = self._attack_start(600)
        total = 0
        for _ in range(self.rng.randint(4, 8)):
            ts += timedelta(seconds=self.rng.uniform(20, 90))
            size = self.rng.randint(300_000_000, 900_000_000)
            total += size
            self.firewall(ts, "accept", src, dst, 443)
            self.zeek_conn(ts, src, dst, 443, service="ssl", duration=self.rng.uniform(60, 400),
                           orig_bytes=size, resp_bytes=self.rng.randint(2000, 9000))
        return {"scenario": "data_exfiltration", "source_ip": src, "dest_ip": dst, "bytes": total}

    def dns_tunneling(self) -> Dict:
        """Data smuggled out in long, random-looking DNS labels."""
        src, domain, count = "10.0.3.40", "cdn-update.example.net", self.rng.randint(80, 150)
        ts = self._attack_start(count * 0.5)
        for _ in range(count):
            ts += timedelta(milliseconds=self.rng.randint(100, 600))
            label = "".join(self.rng.choices("0123456789abcdef", k=self.rng.randint(40, 60)))
            self.zeek_dns(ts, src, f"{label}.{domain}", qtype="TXT")
        return {"scenario": "dns_tunneling", "source_ip": src, "domain": domain, "queries": count}

    def cloud_takeover(self) -> Dict:
        """AWS: console password guessing, then persistence through a new admin user."""
        ip, victim, new_user = self.attacker_ip(), "carol", "support-automation"
        ts = self._attack_start(300)
        agent = "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
        for _ in range(self.rng.randint(8, 15)):
            ts += timedelta(seconds=self.rng.uniform(2, 10))
            self.cloudtrail(ts, "signin.amazonaws.com", "ConsoleLogin", ip, victim, agent,
                            response={"ConsoleLogin": "Failure"})
        ts += timedelta(seconds=20)
        self.cloudtrail(ts, "signin.amazonaws.com", "ConsoleLogin", ip, victim, agent,
                        response={"ConsoleLogin": "Success"})
        steps = [("CreateUser", {"userName": new_user}),
                 ("AttachUserPolicy", {"userName": new_user,
                                       "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
                 ("CreateAccessKey", {"userName": new_user})]
        for name, params in steps:
            ts += timedelta(seconds=self.rng.uniform(10, 40))
            self.cloudtrail(ts, "iam.amazonaws.com", name, ip, victim, agent, params=params)
        return {"scenario": "cloud_takeover", "source_ip": ip, "username": victim}

    @property
    def scenarios(self) -> Dict[str, Callable[[], Dict]]:
        return {"brute_force": self.brute_force, "port_scan": self.port_scan,
                "sql_injection": self.sql_injection,
                "privilege_escalation": self.privilege_escalation,
                "account_takeover": self.account_takeover,
                "lateral_movement": self.lateral_movement, "beaconing": self.beaconing,
                "data_exfiltration": self.data_exfiltration, "dns_tunneling": self.dns_tunneling,
                "cloud_takeover": self.cloud_takeover}

    # -- output ---------------------------------------------------------------

    def generate(self, normal: int = 800, scenarios: Optional[List[str]] = None,
                 sources: Optional[List[str]] = None) -> List[Dict]:
        """Fill self.events. Returns ground truth: one description per injected attack."""
        self.add_normal_traffic(normal, sources)
        names = list(self.scenarios) if scenarios is None else scenarios
        truth = [self.scenarios[name]() for name in names]
        if sources:
            self.events = [e for e in self.events if e[1] in sources]
        self.events.sort(key=lambda e: e[0])
        return truth

    def by_source(self) -> Dict[str, List[str]]:
        grouped: Dict[str, List[str]] = {}
        for _, source, line in self.events:
            grouped.setdefault(source, []).append(line)
        return grouped

    def write_files(self, out_dir) -> Dict[str, Path]:
        """Write one '<log_source>.log' file per source."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = {}
        for source, lines in self.by_source().items():
            paths[source] = out_dir / f"{source}.log"
            paths[source].write_text("\n".join(lines) + "\n", encoding="utf-8")
        return paths

    def stream(self, out_dir, rate: float = 10) -> None:
        """Append events to the log files in order, 'rate' lines per second (Ctrl+C to stop)."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        handles = {}
        try:
            for _, source, line in self.events:
                if source not in handles:
                    handles[source] = open(out_dir / f"{source}.log", "a", encoding="utf-8")
                handles[source].write(line + "\n")
                handles[source].flush()
                time.sleep(1 / rate)
        finally:
            for handle in handles.values():
                handle.close()


def main():
    parser = argparse.ArgumentParser(description="ARGUS synthetic log generator")
    parser.add_argument("--out", default=str(ROOT / "data" / "generated"), help="output directory")
    parser.add_argument("--normal", type=int, default=800, help="number of normal events")
    parser.add_argument("--scenarios", default="all",
                        help="comma separated attack scenarios, 'all' or 'none'")
    parser.add_argument("--sources", default=None, help="comma separated log sources (default: all)")
    parser.add_argument("--minutes", type=float, default=60, help="time window covered by the logs")
    parser.add_argument("--seed", type=int, default=None, help="seed for reproducible output")
    parser.add_argument("--ingest", action="store_true", help="also ingest the logs into MongoDB")
    parser.add_argument("--stream", action="store_true", help="append lines live instead of at once")
    parser.add_argument("--rate", type=float, default=10, help="lines per second with --stream")
    parser.add_argument("--sample", default=None, help="write a small JSON sample to this path")
    parser.add_argument("--list", action="store_true", help="list the attack scenarios and exit")
    args = parser.parse_args()

    if args.stream:  # timestamps start now so the stream looks live
        generator = LogGenerator(args.seed, datetime.now(timezone.utc),
                                 max(args.normal / args.rate / 60, 1))
    else:
        generator = LogGenerator(args.seed, duration_minutes=args.minutes)

    if args.list:
        for name, func in generator.scenarios.items():
            print(f"{name:22} {func.__doc__.strip()}")
        return

    scenarios = {"all": None, "none": []}.get(args.scenarios, args.scenarios.split(","))
    unknown = [s for s in (scenarios or []) if s not in generator.scenarios]
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    sources = args.sources.split(",") if args.sources else None
    truth = generator.generate(args.normal, scenarios, sources)
    print(f"Generated {len(generator.events)} events, {len(truth)} attack scenario(s)")
    for item in truth:
        print(f"  ⚠ {item}")

    if args.sample:
        sample = [{"log_source": source, "raw": line}
                  for source, lines in generator.by_source().items() for line in lines]
        Path(args.sample).write_text(json.dumps(sample, indent=2) + "\n", encoding="utf-8")
        print(f"✓ Wrote {len(sample)} sample logs to {args.sample}")
        return

    if args.stream:
        print(f"🔄 Streaming to {args.out} at {args.rate} lines/s (Ctrl+C to stop)")
        try:
            generator.stream(args.out, args.rate)
        except KeyboardInterrupt:
            pass
        return

    for source, path in generator.write_files(args.out).items():
        print(f"✓ {source:14} {path}")
    (Path(args.out) / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n")

    if args.ingest:
        from backend.ingestion import ingest_batch
        for source, lines in generator.by_source().items():
            result = ingest_batch(lines, source)
            status = "stored" if result["stored"] else "NOT stored (is MongoDB running?)"
            print(f"  {source:14} {result['count']} logs, {result['parse_errors']} parse errors, {status}")


if __name__ == "__main__":
    main()
