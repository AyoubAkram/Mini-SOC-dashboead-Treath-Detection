"""UDP syslog listener and live file tailing."""

import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))
import fileTail  # noqa: E402
import syslogListener  # noqa: E402

from backend import ingestion  # noqa: E402


def wait_for(condition, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_syslog_listener_receives_udp_messages(db):
    port = free_udp_port()
    stop = threading.Event()
    batcher = ingestion.LogBatcher("syslog", max_size=50, max_age=0.2)
    thread = threading.Thread(target=syslogListener.serve, args=("127.0.0.1", port, batcher, stop), daemon=True)
    thread.start()
    messages = [
        b"<38>1 2026-06-14T15:16:01Z bastion sshd 4321 - - Failed password for root from 203.0.113.7 port 22 ssh2",
        b"<30>Jun 14 15:16:02 web-01 cron[77]: (root) CMD (run-parts /etc/cron.hourly)",
        b"<13>1 2026-06-14T15:16:03Z host app - - - one\n<13>1 2026-06-14T15:16:04Z host app - - - two\n",
        b"\xff\xfe not syslog at all",
    ]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(40):  # the listener may need a moment to bind
                client.sendto(messages[0], ("127.0.0.1", port))
                if wait_for(lambda: db.logs.count_documents({}) >= 1, timeout=0.25):
                    break
            db.logs.delete_many({})
            for message in messages:
                client.sendto(message, ("127.0.0.1", port))
        assert wait_for(lambda: db.logs.count_documents({}) == 5)
    finally:
        stop.set()
        thread.join(timeout=3)
    assert not thread.is_alive()
    failed = db.logs.find_one({"event_type": "login_failed"})
    assert failed["log_source"] == "syslog" and failed["source_ip"] == "203.0.113.7"
    assert db.logs.count_documents({"extra.format": "rfc3164"}) == 1
    assert db.logs.count_documents({"extra.parse_error": True}) == 1
    assert {d["message"] for d in db.logs.find({"process": "app"})} == {"one", "two"}


AUTH_LINE = "Jun 14 15:16:0{n} bastion sshd[1]: Failed password for root from 203.0.113.7 port 100{n} ssh2\n"


def test_file_tailer_reads_only_new_complete_lines(db, tmp_path):
    auth = tmp_path / "linux_auth.log"
    auth.write_text(AUTH_LINE.format(n=1))
    (tmp_path / "notes.log").write_text("not a known source\n")
    (tmp_path / "web.txt").write_text("wrong extension\n")

    tailer = fileTail.FileTailer(tmp_path)
    assert tailer.log_files() == [auth]
    assert tailer.poll() == []  # existing content is skipped by default

    with open(auth, "a") as handle:
        handle.write(AUTH_LINE.format(n=2) + AUTH_LINE.format(n=3)[:40])  # second line half written
    (result,) = tailer.poll()
    assert result["count"] == 1 and result["stored"] and result["parse_errors"] == 0
    assert tailer.poll() == []

    with open(auth, "a") as handle:
        handle.write(AUTH_LINE.format(n=3)[40:])
    (result,) = tailer.poll()
    assert result["count"] == 1 and result["parse_errors"] == 0  # the completed line parses cleanly
    assert sorted(d["source_port"] for d in db.logs.find()) == [1002, 1003]

    # a file created after start is read from its beginning
    (tmp_path / "web.log").write_text('10.0.0.1 - - [14/Jun/2026:15:16:01 +0000] "GET / HTTP/1.1" 200 5\n')
    (result,) = tailer.poll()
    assert db.logs.count_documents({"log_source": "web"}) == 1

    # truncation / rotation restarts from the top
    auth.write_text(AUTH_LINE.format(n=4))
    (result,) = tailer.poll()
    assert result["count"] == 1 and db.logs.count_documents({"source_port": 1004}) == 1


def test_file_tailer_from_start(db, tmp_path):
    (tmp_path / "linux_auth.log").write_text(AUTH_LINE.format(n=1) + AUTH_LINE.format(n=2))
    (result,) = fileTail.FileTailer(tmp_path, from_start=True).poll()
    assert result["count"] == 2 and db.logs.count_documents({}) == 2
