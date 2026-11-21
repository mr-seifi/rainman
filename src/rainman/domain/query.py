"""Hunter query language — a store-agnostic parser.

A query is whitespace-separated terms, all of which must match (AND):

    type:endpoint code:403 -tag:archive login
    type:parameter name:redirect*|url|next reflected:true
    type:ip links:>=4            new:last            stale:30d

- ``key:value``     field or prop match; ``*`` is a wildcard, ``|`` means OR
- ``key:>=N``       numeric comparison (``>``, ``>=``, ``<``, ``<=``)
- ``-term``         negation
- ``"two words"``   quoting, for values with spaces (``title:"admin panel"``)
- bare words        substring match on value / notes / tags

The parser only produces ``Term`` values; each store adapter compiles them
(see ``sqlite_repo.query``). Which keys are fields vs. props is the store's
business, except for the aliases below.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

# Short spellings hunters actually type.
ALIASES = {
    "code": "status_code",
    "len": "content_length",
    "size": "content_length",
    "ct": "content_type",
    "sev": "severity",
    "src": "source",
    "tags": "tag",
}

_TOKEN = re.compile(r'-?(?:[A-Za-z_][\w\-]*:)?(?:"[^"]*"|\S+)')
_KEYED = re.compile(r'^([A-Za-z_][\w\-]*):(.*)$', re.S)
_OP = re.compile(r"^(>=|<=|>|<)(.+)$")
_DURATION = re.compile(r"^(\d+)([mhdw])$")
_UNIT = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


@dataclass
class Term:
    key: Optional[str]            # None → free-text
    values: list[str] = field(default_factory=list)   # OR alternatives
    op: str = "="                 # = > >= < <=
    negate: bool = False


def parse_query(q: str) -> list[Term]:
    terms: list[Term] = []
    for tok in _TOKEN.findall(q or ""):
        negate = tok.startswith("-") and len(tok) > 1
        if negate:
            tok = tok[1:]
        key: Optional[str] = None
        val = tok
        m = _KEYED.match(tok)
        # "https://x" is a URL, not key "https"
        if m and not m.group(2).startswith("//") and not tok.startswith('"'):
            key, val = m.group(1).lower(), m.group(2)
            key = ALIASES.get(key, key)
        quoted = len(val) >= 2 and val[0] == '"' and val[-1] == '"'
        if quoted:
            val = val[1:-1]
        op = "="
        if key and not quoted:
            mo = _OP.match(val)
            if mo:
                op, val = mo.group(1), mo.group(2)
        values = [val] if quoted else [v for v in val.split("|") if v != ""]
        if not values:
            continue
        terms.append(Term(key=key, values=values, op=op, negate=negate))
    return terms


def parse_when(value: str, now: Optional[datetime] = None) -> Optional[datetime]:
    """``24h`` / ``7d`` / ``2w`` / ``30m`` → that long ago; otherwise an ISO
    date or datetime. Returns None when it is neither."""
    now = now or datetime.now(timezone.utc)
    m = _DURATION.match(value.strip().lower())
    if m:
        return now - timedelta(**{_UNIT[m.group(2)]: int(m.group(1))})
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Leads — pre-baked hunts, each just a saved query. The UI shows them with live
# counts; agents get the same list (PROPOSAL §15 ``find_patterns``).
# ---------------------------------------------------------------------------

LEADS: list[dict] = [
    {"key": "new", "name": "New since last import",
     "why": "Fresh attack surface — nobody has looked at it yet.",
     "query": "new:last"},
    {"key": "new_hosts", "name": "New hosts this week",
     "why": "Recently appeared subdomains are often unhardened.",
     "query": "type:subdomain new:7d"},
    {"key": "findings", "name": "Open findings",
     "why": "Scanner hits and hunches that still need a verdict.",
     "query": "type:finding -status:done|ignored|out_of_scope"},
    {"key": "status_changed", "name": "Status code changed",
     "why": "An endpoint that flipped (403→200, 200→500) changed behaviour.",
     "query": "type:endpoint has:status_code_history"},
    {"key": "auth_walls", "name": "401 / 403 endpoints",
     "why": "Access-control boundaries — bypass and IDOR candidates.",
     "query": "type:endpoint code:401|403"},
    {"key": "errors", "name": "5xx endpoints",
     "why": "Server errors hint at unhandled input and verbose stack traces.",
     "query": "type:endpoint code:5*"},
    {"key": "sensitive_paths", "name": "Sensitive-looking paths",
     "why": "Backups, VCS metadata, configs, API docs and debug handlers.",
     "query": "type:endpoint value:*/.git*|*/.env*|*backup*|*.bak|*.sql|*.zip|*.tar.gz"
              "|*swagger*|*api-docs*|*openapi*|*graphql*|*actuator*|*phpinfo*|*/debug*"
              "|*/console*|*.config|*/server-status*"},
    {"key": "dev_hosts", "name": "Dev / staging / internal hosts",
     "why": "Non-production hosts tend to run older code with weaker auth.",
     "query": "type:subdomain value:dev*|*-dev*|*.dev.*|*stag*|*uat*|*qa.*|*test*|*internal*"
              "|*admin*|*jenkins*|*gitlab*|*jira*|*grafana*|*kibana*|*vpn*|*beta*|*sandbox*|*preprod*"},
    {"key": "reflected_params", "name": "Reflected parameters",
     "why": "Input echoed in the response — XSS / injection candidates.",
     "query": "type:parameter reflected:true"},
    {"key": "juicy_params", "name": "Juicy parameter names",
     "why": "Names that map to redirect, SSRF, LFI, IDOR and command bugs.",
     "query": "type:parameter name:redirect*|return*|next|url|uri|dest*|target|callback|continue"
              "|file*|path|page|template|include|doc*|cmd|exec|query|host|domain|id|*_id|uid"
              "|user*|account*|token|key|debug|admin|role"},
    {"key": "js_endpoints", "name": "Endpoints found in JavaScript",
     "why": "Routes referenced only from scripts are often undocumented APIs.",
     "query": "type:endpoint tag:js-sourced"},
    {"key": "archive_only", "name": "Archive-only endpoints",
     "why": "Seen in archives but never probed — forgotten features.",
     "query": "type:endpoint tag:archive -has:status_code"},
    {"key": "shared_infra", "name": "Shared infrastructure",
     "why": "IPs and certificates serving several hosts — vhost confusion, lateral scope.",
     "query": "type:ip|certificate links:>=4"},
    {"key": "odd_services", "name": "Non-web services",
     "why": "Databases, admin ports and forgotten daemons exposed to the internet.",
     "query": "type:service -port:80|443"},
    {"key": "stale", "name": "Not seen for 30 days",
     "why": "Assets that dropped out of recon — decommissioned, or takeover candidates.",
     "query": "type:subdomain stale:30d"},
]
