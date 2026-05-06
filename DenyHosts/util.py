import logging
import logging.handlers
import re
import socket
import sys
import time
from email.mime.text import MIMEText
from socket import gethostbyname
from subprocess import Popen, PIPE
from textwrap import dedent
from typing import Any, Optional, Union

from .constants import BSD_STYLE, TIME_SPEC_LOOKUP
from .regex import TIME_SPEC_REGEX

debug = logging.getLogger("util").debug
ipv4_regex = re.compile(r"^([0-9]+\.){3}[0-9]+$")


def gethostbyname(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        m = re.match(r"^(?P<last>\d+)\.ip-(?P<a>\d+)-(?P<b>\d+)-(?P<c>\d+)\.", hostname)
        if m:
            a, b, c, last = m.group("a", "b", "c", "last")
            return f"{a}.{b}.{c}.{last}"
        raise


def setup_logging(prefs: Any, enable_debug: int, verbose: int, daemon: int) -> None:
    daemon_log = prefs.get("DAEMON_LOG")
    if daemon_log:
        fh = logging.handlers.RotatingFileHandler(daemon_log, "a", 1024 * 1024, 7)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            prefs.get("DAEMON_LOG_MESSAGE_FORMAT"), prefs.get("DAEMON_LOG_TIME_FORMAT")
        )
        fh.setFormatter(formatter)
        logging.getLogger().addHandler(fh)
        if enable_debug:
            logging.getLogger().setLevel(logging.DEBUG)
        else:
            logging.getLogger().setLevel(logging.INFO)

        info = logging.getLogger("denyhosts").info
        info("DenyHosts launched with the following args:")
        info("   %s", " ".join(sys.argv))
        prefs.dump_to_logger()


def die(msg: str, ex: Optional[Any] = None) -> None:
    print(msg)
    if ex:
        print(ex)
    sys.exit(1)


def is_true(s: Optional[str]) -> bool:
    if s is None:
        return False
    return s.lower() in ("1", "t", "true", "y", "yes")


def is_false(s: Optional[str]) -> bool:
    return not is_true(s)


def calculate_seconds(timestr: Union[int, str], zero_ok: bool = False) -> int:
    if type(timestr) is int:
        return timestr

    m = TIME_SPEC_REGEX.search(timestr)
    if not m:
        raise Exception("Invalid time specification: string format error: %s", timestr)

    units = int(m.group("units"))
    period = m.group("period") or "s"

    if units == 0 and not zero_ok:
        raise Exception("Invalid time specification: units = 0")

    seconds = units * TIME_SPEC_LOOKUP[period]
    return seconds


def parse_host(line: str) -> str:
    try:
        vals = line.split(":")

        if len(vals) == 1:
            form = vals[0]
        else:
            form = vals[1]

        host = form.strip()
    except Exception:
        host = ""
    return host


def send_email(prefs: Any, report_str: str) -> None:
    recipients = prefs["ADMIN_EMAIL"].split(",")
    msg = (
        dedent("""
    From: {0}
    To: {1}
    Subject: {2}
    Date: {3}

    """)
        .lstrip()
        .format(
            prefs.get("SMTP_FROM"),
            prefs.get("ADMIN_EMAIL"),
            prefs.get("SMTP_SUBJECT"),
            time.strftime(prefs.get("SMTP_DATE_FORMAT")),
        )
    )

    msg += report_str
    try:
        method = prefs.get("EMAIL_METHOD")
        if is_true(prefs.get("SMTP_SSL")):
            smtp = SMTP_SSL()
        else:
            smtp = SMTP()

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            smtp.set_debuglevel(1)

        smtp.connect(prefs.get("SMTP_HOST"), prefs.get("SMTP_PORT"))

        if smtp.ehlo()[0] == 250:
            if smtp.has_extn("starttls"):
                code, resp = smtp.starttls()
                if code != 220:
                    raise SMTPResponseException(code, resp)
                code, resp = smtp.ehlo()
                if code != 250:
                    raise SMTPResponseException(code, resp)
            else:
                code, resp = smtp.helo()
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)

            username = prefs.get("SMTP_USERNAME")
            password = prefs.get("SMTP_PASSWORD")

            if username and password:
                smtp.login(username, password)

            smtp.sendmail(prefs.get("SMTP_FROM"), recipients, msg)
            debug("sent email to: %s" % prefs.get("ADMIN_EMAIL"))
        elif method == "SENDMAIL":
            msg = MIMEText(report_str)
            msg["From"] = prefs.get("SMTP_FROM")
            msg["To"] = prefs.get("ADMIN_EMAIL")
            msg["Subject"] = prefs.get("SMTP_SUBJECT")
            p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE)
            p.communicate(msg.as_string())
        elif method == "MAIL":
            p = Popen(
                ["mail", "-s", prefs.get("SMTP_SUBJECT")] + recipients, stdin=PIPE
            )
            p.communicate(report_str)
        elif method == "STDOUT":
            print(report_str)
        else:
            raise Exception("Unknown e-mail method: %s" % method)
    except Exception as e:
        print("Error sending email")
        print(e)
        print("Email message follows:")
        print(report_str)

    try:
        smtp.quit()
    except Exception:
        pass


def normalize_whitespace(string: str) -> str:
    return " ".join(string.split())


def hostname_lookup(process_host: str) -> str:
    if re.match(ipv4_regex, process_host):
        return process_host
    ip = gethostbyname(process_host)
    return ip


def is_valid_ip_address(process_ip: str) -> bool:
    from ipaddress import ip_address

    ip = ip_address(process_ip)

    if (
        ip is None
        or ip.is_reserved
        or ip.is_private
        or ip.is_loopback
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
    ):
        return False
    return True


def get_user_input(prompt: str) -> str:
    try:
        response = raw_input(prompt)
    except NameError:
        response = input(prompt)
    return response
