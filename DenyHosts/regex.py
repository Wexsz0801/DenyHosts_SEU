import re

#################################################################################
# REGULAR EXPRESSIONS ARE COOL.  Check out Kodos (http://kodos.sourceforge.net) #
#################################################################################

# ==== Shared host patterns =====================================================
# IPv4: 1.2.3.4
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

# IPv6: broad but practical match for hextets/:: compression, with optional zone id (%eth0, %en0, etc.)
# We avoid ultra-strict RFC validation to keep the parser resilient across syslog variants.
_IPV6 = r"[0-9A-Fa-f:]+(?:%[0-9A-Za-z_.-]+)?"

# Either IPv4 or IPv6
_HOST = rf"(?:{_IPV4}|{_IPV6})"

# ------------------------------------------------------------------------------
SSHD_FORMAT_REGEX = re.compile(r""".* (sshd.*?:|\[sshd\]) (?P<message>.*)""")
#SSHD_FORMAT_REGEX = re.compile(r""".* sshd.*: (?P<message>.*)""")

FAILED_ENTRY_REGEX = re.compile(
    rf"""Failed (?P<method>\S*) for (?P<invalid>invalid user |illegal user )?(?P<user>.*) """
    rf"""from (?:(?:::ffff:)?)?(?P<host>{_HOST})(?: port \d+)?(?: ssh2)?$"""
)

FAILED_ENTRY_REGEX2 = re.compile(
    rf"""(?P<invalid>(Illegal|Invalid)) user (?P<user>.*) from (::ffff:)?(?P<host>{_IPV4})([\sport\d]+)?$"""
)

# Authentication failure (accept IPv4 or IPv6)
FAILED_ENTRY_REGEX3 = re.compile(
    rf"""Authentication failure for (?P<user>.+?) .*from (?P<host>{_HOST})"""
)

# Fallback: very permissive host capture (kept as-is)
FAILED_ENTRY_REGEX4 = re.compile(
    r"""Authentication failure for (?P<user>.*) .*from (?P<host>.*)"""
)

FAILED_ENTRY_REGEX5 = re.compile(
    r"""User (?P<user>.*) .*from (?P<host>.*) not allowed because none of user's groups are listed in AllowGroups$"""
)

FAILED_ENTRY_REGEX6 = re.compile(
    rf"""Did not receive identification string .*from (::ffff:)?(?P<host>{_IPV4})"""
)

FAILED_ENTRY_REGEX7 = re.compile(
    rf"""User (?P<user>.*) .*from (::ffff:)?(?P<host>{_IPV4}) not allowed because not listed in AllowUsers"""
)

FAILED_ENTRY_REGEX8 = re.compile(
    r"""authentication error for (?P<user>.*) .*from (?P<host>.*)"""
)

FAILED_ENTRY_REGEX9 = re.compile(
    rf"""Connection closed by (?P<host>{_HOST})(?: port \d+)? \[preauth\]"""
)

# these are reserved for future versions
FAILED_ENTRY_REGEX10 = None
FAILED_ENTRY_REGEX11 = None

# this should match the highest num failed_entry_regex + 1
FAILED_ENTRY_REGEX_NUM = 10

FAILED_ENTRY_REGEX_RANGE = list(range(1, FAILED_ENTRY_REGEX_NUM))
FAILED_ENTRY_REGEX_MAP = {}

# create a hash of the failed entry regex'es indexed from 1 .. FAILED_ENTRY_REGEX_NUM
for i in FAILED_ENTRY_REGEX_RANGE:
    if i == 1:
        extra = ""
    else:
        extra = "%i" % i
    rx = eval("FAILED_ENTRY_REGEX%s" % extra)
    FAILED_ENTRY_REGEX_MAP[i] = rx

# Accepted login (now accepts IPv6 + optional zone ids, keeps old IPv4 + extras)
SUCCESSFUL_ENTRY_REGEX = re.compile(
    rf"""Accepted (?P<method>\S+) for (?P<user>.+?) from (::ffff:)?(?P<host>{_HOST})(?: port \d+)?(?: ssh2)?"""
    rf"""(?:: (?:DSA|RSA))?(?: (?:SHA256:\S{{43}}))?(?:\S[0-9a-f](?::\S[0-9a-f]){{15}})?$""",
    re.IGNORECASE,
)

TIME_SPEC_REGEX = re.compile(r"""(?P<units>\d*)\s*(?P<period>[smhdwy])?""")

ALLOWED_REGEX = re.compile(
    r"""(?P<first_3bits>\d{1,3}\.\d{1,3}\.\d{1,3}\.)((?P<fourth>\d{1,3})|(?P<ip_wildcard>\*)|\[(?P<ip_range>\d{1,3}-\d{1,3})\])"""
)

PREFS_REGEX = re.compile(r"""(?P<name>.*?)\s*[:=]\s*(?P<value>.*)""")

FAILED_DOVECOT_ENTRY_REGEX = re.compile(
    rf"""dovecot.*authentication failure.*ruser=(?P<user>\S+).*rhost=(?P<host>{_IPV4}).*"""
)
