import std/[unittest, strutils]
import ../src/log_ingest

suite "log_ingest":
  test "parses SSH failed password with src IP extraction":
    let ev = parseLogLine("Jul 19 10:22:01 host sshd[1234]: Failed password for root from 203.0.113.10 port 51234 ssh2", "auth.log")
    check ev.category == "auth"
    check ev.process == "sshd"
    check ev.srcIp == "203.0.113.10"
    check "Failed password" in ev.message

  test "parses sudo line without a PID":
    let ev = parseLogLine("Jul 19 10:23:00 host sudo: lrusso : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls", "auth.log")
    check ev.category == "auth"
    check ev.process == "sudo"

  test "direct root console login (journald-timestamped) is categorized as auth, not syslog":
    let ev = parseLogLine("2026-07-19T11:44:30+02:00 DESKTOP-AR2TIB7 login[500]: ROOT LOGIN  on '/dev/pts/4'", "auth.log")
    check ev.category == "auth"
    check ev.process == "login"
    check "ROOT LOGIN" in ev.message

  test "regular non-root login session is still categorized as auth via the login process":
    let ev = parseLogLine("2026-07-19T11:44:40+02:00 DESKTOP-AR2TIB7 login[501]: pam_unix(login:session): session opened for user ubuntu(uid=1000) by ubuntu(uid=0)", "auth.log")
    check ev.category == "auth"
    check ev.process == "login"

  test "parses Apache/Nginx combined access log":
    let ev = parseLogLine("""203.0.113.10 - - [19/Jul/2026:10:22:10 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0""", "web")
    check ev.category == "web"
    check ev.srcIp == "203.0.113.10"
    check ev.httpMethod == "GET"
    check ev.path == "/../../etc/passwd"
    check ev.status == "404"

  test "parses kernel/dmesg bracketed timestamp":
    let ev = parseLogLine("[12345.678901] Out of memory: Killed process 4321 (python3)", "kernel")
    check ev.category == "kernel"
    check "Out of memory" in ev.message

  test "parses syslog with priority prefix":
    let ev = parseLogLine("<134>daemon restarted successfully", "syslog")
    check ev.category == "syslog"
    check ev.message == "daemon restarted successfully"

  test "unrecognized line falls back to generic, nothing dropped":
    let ev = parseLogLine("some completely unstructured line of text", "custom-agent")
    check ev.category == "generic"
    check ev.message == "some completely unstructured line of text"

  test "parses journald-exported line (ISO8601 timestamp, non-auth daemon)":
    let ev = parseLogLine("2026-07-19T11:44:43.316329+02:00 DESKTOP-AR2TIB7 polkitd[3802]: Acquired the name org.freedesktop.PolicyKit1 on the system bus", "auth.log")
    check ev.category == "syslog"
    check ev.process == "polkitd"
    check ev.hostname == "DESKTOP-AR2TIB7"
    check ev.message == "Acquired the name org.freedesktop.PolicyKit1 on the system bus"

  test "journald line without a PID in brackets still extracts the process":
    let ev = parseLogLine("2026-07-19T11:44:43+02:00 host somedaemon: plain message here", "auth.log")
    check ev.category == "syslog"
    check ev.process == "somedaemon"
    check ev.message == "plain message here"

  test "sshd inside a journald-timestamped line still parses as auth (higher priority)":
    let ev = parseLogLine("2026-07-19T11:44:43+02:00 host sshd[123]: Failed password for root from 203.0.113.10 port 22 ssh2", "auth.log")
    check ev.category == "auth"
    check ev.process == "sshd"
    check ev.srcIp == "203.0.113.10"

  test "classic syslog date format is not mistaken for journald ISO8601":
    let ev = parseLogLine("Jul 19 10:22:01 host somedaemon[1]: hello", "auth.log")
    check ev.category == "generic"

