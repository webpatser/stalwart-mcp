#!/usr/bin/env python3
"""End-to-end MCP client for an INSTALLED stalwart-mcp binary.

Speaks JSON-RPC over stdio and streamable HTTP against a live Stalwart.

Environment (required): STALWART_TEST_URL, STALWART_TEST_USER, STALWART_PASSWORD.
Environment (only with --send): STALWART_TEST_SEND_TO.

Credentials, the server host and addresses come from the environment only and
are never printed: every printed line has them masked and email addresses
redacted. Config files and logs live in a private temporary directory that is
removed at the end (unless --keep-logs).

The script works only on what it creates (one draft, one masked address, a
disabled vacation response it restores) and removes it again, printing a
CLEANUP line per item. By default it sends no mail; --send sends exactly one
message to STALWART_TEST_SEND_TO.

Usage: python3 -I scripts/e2e.py [--send] [--bin PATH] [--port N] [--keep-logs]
"""

import argparse
import base64
import http.client
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

VERSION = "1.1.1-3"
ACCOUNT = "e2e"
OTHER_ACCOUNT = "e2e-other"
TS = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

# Set in main() from the command line.
BIN = ""
PORT = 0
ADDR = ""
WORKDIR = ""

EXPECTED_TOOLS = {
    "mail_list_folders", "mail_list_recent", "mail_search", "mail_get",
    "mail_flag", "mail_move", "mail_draft", "mail_send", "mail_bulk_junk",
    "mail_bulk_delete", "mail_bulk_read", "spam_train",
    "mail_masked_list", "mail_masked_create", "mail_masked_disable",
    "mail_vacation_get", "mail_vacation_set", "quota_get", "identity_list",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+=-]+@[A-Za-z0-9.-]+")
SENSITIVE_VARS = ["STALWART_PASSWORD", "STALWART_TEST_USER", "STALWART_TEST_URL",
                  "STALWART_TEST_SEND_TO"]


def _sensitive():
    """Values that must never appear in output: env values and the server host."""
    vals = []
    for var in SENSITIVE_VARS:
        v = os.environ.get(var, "")
        if v:
            vals.append(v)
    host = urllib.parse.urlparse(os.environ.get("STALWART_TEST_URL", "")).hostname
    if host:
        vals.append(host)
    return sorted(set(vals), key=len, reverse=True)


def red(s):
    s = str(s)
    for v in _sensitive():
        s = s.replace(v, "***")
    return EMAIL_RE.sub("***@***", s)


RESULTS = {}


def check(section, name, ok, reason=""):
    RESULTS.setdefault(section, [0, 0])
    RESULTS[section][0 if ok else 1] += 1
    tag = "PASS" if ok else "FAIL"
    print(red(f"{tag} [{section}] {name}: {reason}"), flush=True)
    return ok


def info(msg):
    print(red(f"INFO {msg}"), flush=True)


def cleanup(msg):
    print(red(f"CLEANUP {msg}"), flush=True)


def skip(section, name, reason):
    print(red(f"SKIP [{section}] {name}: {reason}"), flush=True)


def utc(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def work(name):
    return os.path.join(WORKDIR, name)


# ---------------------------------------------------------------- config

def write_config(path, *, send=False, masked=False, vacation=False,
                 secret=None, allowed_hosts=None):
    url = os.environ["STALWART_TEST_URL"]
    user = os.environ["STALWART_TEST_USER"]
    lines = [
        f'default_account = "{ACCOUNT}"',
        "",
        "[[accounts]]",
        f'name = "{ACCOUNT}"',
        f"url = {json.dumps(url)}",
        f"username = {json.dumps(user)}",
        'password_env = "STALWART_PASSWORD"',
        "",
        "[server]",
        f'bind = "{ADDR}"',
        f"allowed_hosts = {json.dumps(allowed_hosts or [])}",
        "",
        "[capabilities]",
        f"send = {str(send).lower()}",
        "spam_training = false",
        f"masked_email = {str(masked).lower()}",
        f"vacation = {str(vacation).lower()}",
        "delete = false",
        "",
        "[notifications]",
        "enabled = true",
    ]
    if secret is not None:
        lines += ["", "[auth]", f"secret = {json.dumps(secret)}"]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def log_tail(path, n=3):
    try:
        with open(path, errors="replace") as f:
            return " | ".join(line.strip() for line in f.readlines()[-n:])
    except OSError:
        return ""


def open_log(label):
    path = work(f"{label}.log")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return path, os.fdopen(fd, "w")


# ---------------------------------------------------------------- stdio client

class Stdio:
    def __init__(self, cfg, label):
        self.log, self.logf = open_log(label)
        self.proc = subprocess.Popen(
            [BIN, "-c", cfg, "serve"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.logf, env=os.environ)
        self.q = queue.Queue()
        self.next_id = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.q.put(json.loads(line))
            except ValueError:
                self.q.put({"_unparsed": line.decode(errors="replace")[:200]})
        self.q.put(None)

    def _write(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)

    def request(self, method, params=None, timeout=90):
        self.next_id += 1
        rid = self.next_id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError(f"{method}: no response in {timeout}s")
            try:
                m = self.q.get(timeout=left)
            except queue.Empty:
                raise TimeoutError(f"{method}: no response in {timeout}s")
            if m is None:
                raise RuntimeError(f"{method}: server exited ({log_tail(self.log)})")
            if "method" in m and "id" in m:  # server-to-client request
                self._write({"jsonrpc": "2.0", "id": m["id"], "result": {}})
                continue
            if m.get("id") == rid:
                return m

    def initialize(self):
        r = self.request("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "stalwart-mcp-e2e", "version": "1"}})
        self.notify("notifications/initialized")
        return r

    def call(self, name, args=None):
        """Returns (ok, text)."""
        return tool_result(self.request("tools/call", {"name": name, "arguments": args or {}}))

    def call_json(self, name, args=None):
        ok, text = self.call(name, args)
        if not ok:
            raise RuntimeError(f"{name} failed: {text[:300]}")
        return json.loads(text)

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(5)
        self.logf.close()


def tool_result(r):
    """(ok, text) from a tools/call JSON-RPC response."""
    if r is None:
        return False, "no response"
    if "error" in r:
        return False, r["error"].get("message", json.dumps(r["error"]))
    res = r.get("result", {})
    text = "\n".join(c.get("text", "") for c in res.get("content", [])
                     if c.get("type") == "text")
    return (not res.get("isError", False)), text


# ---------------------------------------------------------------- direct JMAP

_DEFAULT_PORTS = {"http": 80, "https": 443}


def origin(url):
    """(scheme, host, effective port) of `url`, lowercased; None if not http(s) or malformed."""
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        return None
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    return scheme, host, port if port is not None else _DEFAULT_PORTS[scheme]


def same_origin(a, b):
    """True only when both URLs have the same scheme, host and effective port."""
    oa = origin(a)
    return oa is not None and oa == origin(b)


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only within the origin of `base` (at most 3 hops), so the
    Basic credential never reaches another scheme, host or port."""

    max_redirections = 3

    def __init__(self, base):
        super().__init__()
        self.base = base

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not same_origin(self.base, newurl):
            fp.close()
            raise RuntimeError(
                f"JMAP request redirected ({code}) to another origin; refusing to follow")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_jmap(opener, req):
    """Open `req`; an unfollowed or exhausted redirect is a failure."""
    try:
        r = opener.open(req, timeout=30)
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            e.close()
            raise RuntimeError(f"JMAP request redirected ({e.code}); not followed") from None
        raise
    if 300 <= r.status < 400:
        r.close()
        raise RuntimeError(f"JMAP request redirected ({r.status}); not followed")
    return r


class Jmap:
    """Minimal JMAP caller for cleanup steps that have no (enabled) MCP tool."""

    def __init__(self, account_id):
        base = os.environ["STALWART_TEST_URL"]
        url = base.rstrip("/")
        if not url.endswith("/.well-known/jmap"):
            url += "/.well-known/jmap"
        if origin(url) is None:
            raise RuntimeError("STALWART_TEST_URL is not an http(s) URL")
        self.host = urllib.parse.urlparse(url).hostname
        self.opener = urllib.request.build_opener(_SameOriginRedirect(url))
        cred = f'{os.environ["STALWART_TEST_USER"]}:{os.environ["STALWART_PASSWORD"]}'
        self.auth = "Basic " + base64.b64encode(cred.encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": self.auth})
        with _open_jmap(self.opener, req) as r:
            if not same_origin(url, r.geturl()):
                raise RuntimeError("session redirected to another origin")
            session = json.load(r)
        self.api = session["apiUrl"]
        if urllib.parse.urlparse(self.api).hostname != self.host:
            raise RuntimeError("apiUrl on another host")
        self.account_id = account_id

    def call(self, using, method, args):
        body = json.dumps({
            "using": ["urn:ietf:params:jmap:core", *using],
            "methodCalls": [[method, {"accountId": self.account_id, **args}, "c1"]],
        }).encode()
        req = urllib.request.Request(self.api, data=body, method="POST", headers={
            "Authorization": self.auth, "Content-Type": "application/json"})
        with _open_jmap(self.opener, req) as r:
            resp = json.load(r)
        name, out, _ = resp["methodResponses"][0]
        if name == "error":
            raise RuntimeError(f"{method}: {out}")
        return out

    def sieve_scripts(self):
        out = self.call(["urn:ietf:params:jmap:sieve"], "SieveScript/get",
                        {"ids": None, "properties": ["id", "name", "isActive"]})
        return sorted((s["id"], s.get("name"), bool(s.get("isActive")))
                      for s in out.get("list", []))

    def masked_get(self, mid):
        out = self.call(["urn:stalwart:jmap"], "x:MaskedEmail/get", {"ids": [mid]})
        return next((m for m in out.get("list", []) if m.get("id") == mid), None)

    def masked_destroy(self, mid):
        out = self.call(["urn:stalwart:jmap"], "x:MaskedEmail/set", {"destroy": [mid]})
        return mid in (out.get("destroyed") or [])

    def email_subject(self, eid):
        out = self.call(["urn:ietf:params:jmap:mail"], "Email/get",
                        {"ids": [eid], "properties": ["id", "subject"]})
        e = next((x for x in out.get("list", []) if x.get("id") == eid), None)
        return None if e is None else (e.get("subject") or "")

    def email_destroy(self, eid):
        out = self.call(["urn:ietf:params:jmap:mail"], "Email/set", {"destroy": [eid]})
        return eid in (out.get("destroyed") or [])


# ---------------------------------------------------------------- helpers

def parse_id(text):
    m = re.search(r"ID:\s*([A-Za-z0-9_-]+)", text)
    return m.group(1) if m else None


def real_id(i):
    return bool(i) and not re.fullmatch(r"c\d+", i)


def ids_in(server, folder_id, count=100):
    lst = server.call_json("mail_list_recent", {"folder": folder_id, "count": count})
    return {e["id"]: e for e in lst}


def is_disabled_err(ok, text):
    return (not ok) and "disabled" in text.lower()


# ---------------------------------------------------------------- sections

def section_a(s, ctx):
    r = s.initialize()
    si = r.get("result", {}).get("serverInfo", {})
    check("A", "initialize serverInfo",
          si.get("name") == "stalwart-mcp" and si.get("version") == VERSION,
          f"name={si.get('name')} version={si.get('version')}")

    tools = s.request("tools/list").get("result", {}).get("tools", [])
    names = {t["name"] for t in tools}
    ctx["tool_count"] = len(names)
    check("A", "tools/list", names == EXPECTED_TOOLS,
          f"{len(names)} tools; missing={sorted(EXPECTED_TOOLS - names)} "
          f"extra={sorted(names - EXPECTED_TOOLS)}")

    pr = s.request("prompts/list")
    prompts = pr.get("result", {}).get("prompts")
    check("A", "prompts/list", isinstance(prompts, list),
          f"{len(prompts or [])} prompts: {[p.get('name') for p in prompts or []]}"
          if prompts is not None else str(pr.get("error")))

    rl = s.request("resources/list")
    res = rl.get("result", {}).get("resources")
    check("A", "resources/list", isinstance(res, list) and len(res) > 0,
          f"{len(res or [])} resources: {[x.get('uri') for x in res or []]}"
          if res is not None else str(rl.get("error")))

    ra = s.request("resources/read", {"uri": "mail://accounts"})
    try:
        accts = json.loads(ra["result"]["contents"][0]["text"])
        acct = next(a for a in accts if a["name"] == ACCOUNT)
        ctx["account_id"] = acct["id"]
        ctx["username"] = acct["username"]
        check("A", "resources/read mail://accounts", bool(acct["id"]) and acct["is_default"],
              f"{len(accts)} account(s), default={acct['is_default']}")
    except Exception as e:  # noqa: BLE001
        check("A", "resources/read mail://accounts", False, f"{e} {ra.get('error')}")

    rf = s.request("resources/read", {"uri": f"mail://{ACCOUNT}/folders"})
    try:
        folders = json.loads(rf["result"]["contents"][0]["text"])
        check("A", "resources/read folders", len(folders) > 0, f"{len(folders)} folders")
    except Exception as e:  # noqa: BLE001
        check("A", "resources/read folders", False, f"{e} {rf.get('error')}")


def section_b(s, ctx):
    folders = s.call_json("mail_list_folders")
    roles = {f["role"].lower(): f["id"] for f in folders}
    ctx["roles"] = roles
    need = ["inbox", "drafts", "sent", "trash", "junk"]
    check("B", "mail_list_folders", all(r in roles for r in need),
          f"{len(folders)} folders, roles present: {[r for r in need if r in roles]}")

    recent = s.call_json("mail_list_recent", {"count": 5})
    check("B", "mail_list_recent", isinstance(recent, list) and len(recent) > 0,
          f"{len(recent)} emails")

    ok, text = s.call("mail_search", {"folder": roles.get("inbox"), "limit": 3})
    n = len(json.loads(text)) if ok else -1
    check("B", "mail_search (folder filter)", ok and n >= 0, f"{n} results" if ok else text[:200])
    ok2, text2 = s.call("mail_search", {})
    check("B", "mail_search rejects no filters", not ok2, text2[:120])

    if recent:
        rid = recent[0]["id"]
        ok, text = s.call("mail_get", {"id": rid})
        good = ok and json.loads(text).get("id") == rid
        check("B", "mail_get recent", good, "id matches" if good else text[:200])

    q = s.call_json("quota_get")
    check("B", "quota_get", isinstance(q, list),
          f"{len(q)} quotas: {[(x.get('resourceType'), x.get('scope')) for x in q]}")

    ids = s.call_json("identity_list")
    check("B", "identity_list", len(ids) > 0 and all("@" in i["email"] for i in ids),
          f"{len(ids)} identities")
    user = ctx.get("username", "").lower()
    pick = next((i for i in ids if i["email"].lower() == user), ids[0] if ids else None)
    ctx["identity"] = pick["email"] if pick else None

    m = s.call_json("mail_masked_list")
    ctx["masked_before"] = len(m)
    check("B", "mail_masked_list", isinstance(m, list), f"{len(m)} masked addresses")

    v = s.call_json("mail_vacation_get")
    ctx["vacation_before"] = v
    check("B", "mail_vacation_get", "isEnabled" in v, f"isEnabled={v.get('isEnabled')}")


def draft_flow(s, ctx, jm):
    roles = ctx["roles"]
    ident = ctx["identity"]
    subject = f"stalwart-mcp e2e draft {TS}"
    ctx["draft_subject"] = subject
    ok, text = s.call("mail_draft", {"to": [ident], "subject": subject,
                                     "body": "Automated stalwart-mcp e2e draft. Safe to delete."})
    did = parse_id(text) if ok else None
    if not check("C", "mail_draft real id", ok and real_id(did), f"id={did}" if ok else text[:200]):
        return
    ctx["draft_id"] = did
    try:
        e = s.call_json("mail_get", {"id": did})
        frm = " ".join(e.get("from", []))
        check("C", "mail_get draft", e.get("subject") == subject and "@" in frm
              and ident.lower() in frm.lower(),
              f"subject ok={e.get('subject') == subject}, from={frm}")
        check("C", "draft in Drafts", did in ids_in(s, roles["drafts"]), "listed")

        for action, key, want in [("read", "is_unread", False), ("unread", "is_unread", True),
                                  ("flag", "is_flagged", True), ("unflag", "is_flagged", False)]:
            ok, text = s.call("mail_flag", {"id": did, "action": action})
            e = s.call_json("mail_get", {"id": did}) if ok else {}
            check("C", f"mail_flag {action}", ok and e.get(key) is want,
                  f"{key}={e.get(key)}" if ok else text[:200])

        ok, text = s.call("mail_move", {"id": did, "folder": roles["trash"]})
        in_trash = ok and did in ids_in(s, roles["trash"])
        in_drafts = did in ids_in(s, roles["drafts"])
        check("C", "mail_move to Trash", in_trash and not in_drafts,
              f"in_trash={in_trash} in_drafts={in_drafts}" if ok else text[:200])

        s.call("mail_flag", {"id": did, "action": "unread"})
        ok, text = s.call("mail_bulk_read", {"ids": [did]})
        e = s.call_json("mail_get", {"id": did}) if ok else {}
        check("C", "mail_bulk_read", ok and e.get("is_unread") is False, text[:120])

        skip("C", "mail_bulk_junk live",
             "not run: moving to Junk can train Stalwart's Bayes filter, which notjunk "
             "cannot undo; validation checked instead")
        ok, text = s.call("mail_bulk_junk", {"ids": [did], "action": "bogus"})
        check("C", "mail_bulk_junk rejects bad action", not ok, text[:120])
        ok, text = s.call("mail_bulk_junk", {"ids": []})
        check("C", "mail_bulk_junk rejects empty ids", not ok, text[:120])

        # Default delete mode: back to Drafts first, then mail_bulk_delete moves to Trash.
        ok, text = s.call("mail_move", {"id": did, "folder": roles["drafts"]})
        check("C", "mail_move back to Drafts", ok and did in ids_in(s, roles["drafts"]),
              "listed" if ok else text[:200])
        ok, text = s.call("mail_bulk_delete", {"ids": [did]})
        still_there, _ = s.call("mail_get", {"id": did})
        in_trash = did in ids_in(s, roles["trash"])
        in_drafts = did in ids_in(s, roles["drafts"])
        check("C", "mail_bulk_delete default moves to Trash",
              ok and "trash" in text.lower() and still_there and in_trash and not in_drafts,
              f"{text[:80]}; exists={still_there} in_trash={in_trash} in_drafts={in_drafts}")

        # Permanent mode without capabilities.delete: refused before any request.
        ok, text = s.call("mail_bulk_delete", {"ids": [did], "permanent": True})
        still_there, _ = s.call("mail_get", {"id": did})
        check("C", "mail_bulk_delete permanent disabled",
              is_disabled_err(ok, text) and still_there,
              f"{text[:100]}; still_exists={still_there}")
    finally:
        # Permanent delete is gated off in this config, so remove the draft over
        # JMAP directly, and only if it is still the one this run created.
        try:
            subj = jm.email_subject(did)
            if subj is None:
                cleanup(f"draft {did}: already gone")
            elif subj != subject:
                check("C", "draft cleanup", False, f"{did} is not ours, not touched")
            else:
                destroyed = jm.email_destroy(did)
                gone = jm.email_subject(did) is None
                cleanup(f"draft {did}: destroyed={destroyed} gone={gone}")
                check("C", "draft destroyed", destroyed and gone, "")
        except Exception as e:  # noqa: BLE001
            cleanup(f"draft {did}: FAILED ({type(e).__name__}: {e}); "
                    f"left behind, subject '{subject}'")
            check("C", "draft destroyed", False, "cleanup raised")


def masked_flow(s, ctx, jm):
    desc = f"stalwart-mcp e2e {TS}"
    before = ctx["masked_before"]
    ok, text = s.call("mail_masked_create", {"description": desc, "for_domain": "example.com"})
    if not check("C", "mail_masked_create", ok, "created" if ok else text[:200]):
        return
    created = json.loads(text)
    mid = created["id"]
    try:
        check("C", "masked has generated address", "@" in (created.get("email") or ""),
              f"id={mid} enable={created.get('enable')}")
        lst = s.call_json("mail_masked_list")
        ours = next((m for m in lst if m["id"] == mid), None)
        check("C", "masked listed", ours is not None and ours.get("description") == desc,
              f"count {before} -> {len(lst)}")
        ok, text = s.call("mail_masked_disable", {"id": mid})
        check("C", "mail_masked_disable", ok and json.loads(text).get("enable") is False,
              "enable=false" if ok else text[:200])
        lst = s.call_json("mail_masked_list")
        ours = next((m for m in lst if m["id"] == mid), None)
        check("C", "masked listed disabled", ours is not None and ours.get("enable") is False,
              f"enable={ours and ours.get('enable')}")
    finally:
        try:
            m = jm.masked_get(mid)
            if m is None:
                cleanup(f"masked {mid}: already gone")
            elif m.get("description") != desc:
                check("C", "masked cleanup", False, f"{mid} is not ours, not touched")
            else:
                destroyed = jm.masked_destroy(mid)
                gone = jm.masked_get(mid) is None
                cleanup(f"masked {mid}: destroyed={destroyed} gone={gone}")
                lst = s.call_json("mail_masked_list")
                check("C", "masked destroyed, count restored",
                      destroyed and gone and len(lst) == before
                      and all(x["id"] != mid for x in lst),
                      f"destroyed={destroyed} gone={gone} count={len(lst)} before={before}")
        except Exception as e:  # noqa: BLE001
            cleanup(f"masked {mid}: FAILED ({type(e).__name__}: {e}); "
                    f"left behind, description '{desc}'")
            check("C", "masked destroyed, count restored", False, "cleanup raised")


_S = {}


def restore(prior, s=None):
    s = s or _S["main"]
    if prior.get("isEnabled"):
        raise RuntimeError("refusing to write an enabled vacation response")
    args = {"is_enabled": False}
    for src, dst in [("fromDate", "from_date"), ("toDate", "to_date"), ("subject", "subject"),
                     ("textBody", "text_body"), ("htmlBody", "html_body")]:
        if prior.get(src) is not None:
            args[dst] = prior[src]
    ok, text = s.call("mail_vacation_set", args)
    if not ok:
        info(f"vacation restore call failed: {text[:200]}")


def vacation_flow(s, ctx, jm):
    prior = ctx["vacation_before"]
    if prior.get("isEnabled"):
        skip("C", "vacation writes", "an auto-reply is active; left untouched")
        return
    sieve_before = jm.sieve_scripts()
    ctx["sieve_before"] = sieve_before
    info(f"sieve scripts before: {len(sieve_before)}")
    now = datetime.now(timezone.utc)

    def restore_if_enabled(label):
        v = s.call_json("mail_vacation_get")
        if v.get("isEnabled"):
            restore(prior)
            check("C", label, False, "!!! vacation got ENABLED; restored immediately")
            return False
        return v

    # Negative checks: kept harmless even if validation were broken (start far ahead).
    ok, text = s.call("mail_vacation_set", {"is_enabled": True,
                                            "from_date": "2099-01-01T00:00:00Z",
                                            "subject": f"stalwart-mcp e2e {TS}"})
    check("C", "vacation enable without to_date rejected", not ok and "to_date" in text, text[:120])
    ok, text = s.call("mail_vacation_set", {"is_enabled": True,
                                            "from_date": utc(now + timedelta(days=199)),
                                            "to_date": utc(now + timedelta(days=200)),
                                            "subject": f"stalwart-mcp e2e {TS}"})
    check("C", "vacation to_date 200d rejected", not ok and "90" in text, text[:120])
    v = restore_if_enabled("vacation negative checks")
    if v is not False:
        check("C", "negative checks wrote nothing",
              v == prior and jm.sieve_scripts() == sieve_before,
              f"vacation_equal={v == prior} sieve_equal={jm.sieve_scripts() == sieve_before}")

    test = {"is_enabled": False, "from_date": "2099-01-01T00:00:00Z",
            "to_date": "2099-01-02T00:00:00Z", "subject": f"stalwart-mcp e2e {TS}",
            "text_body": "Automated stalwart-mcp e2e test. Never enabled."}
    try:
        ok, text = s.call("mail_vacation_set", test)
        stored = json.loads(text) if ok else {}
        back = s.call_json("mail_vacation_get")
        want = {"isEnabled": False, "fromDate": test["from_date"], "toDate": test["to_date"],
                "subject": test["subject"], "textBody": test["text_body"]}
        good = ok and all(back.get(k) == val for k, val in want.items()) and stored == back
        check("C", "mail_vacation_set disabled test state", good,
              "read back equal" if good else f"{text[:120]} back_keys={sorted(back)}")
    finally:
        try:
            _vacation_cleanup(s, jm, prior, sieve_before)
        except Exception as e:  # noqa: BLE001
            cleanup(f"vacation/sieve: FAILED ({type(e).__name__}: {e}); "
                    f"check the vacation response (subject 'stalwart-mcp e2e {TS}') "
                    "and any inactive 'vacation' sieve script")
            check("C", "vacation restored", False, "cleanup raised")


def _vacation_cleanup(s, jm, prior, sieve_before):
    restore(prior, s)
    after = s.call_json("mail_vacation_get")
    cleanup(f"vacation response restored: equal={after == prior}")
    check("C", "vacation restored", after == prior, f"equal={after == prior}")
    now_scripts = jm.sieve_scripts()
    before_ids = {x[0] for x in sieve_before}
    added = [x for x in now_scripts if x[0] not in before_ids]
    for sid, name, active in added:
        if name == "vacation" and not active:
            out = jm.call(["urn:ietf:params:jmap:sieve"], "SieveScript/set", {"destroy": [sid]})
            cleanup(f"inactive 'vacation' sieve script {sid}: "
                    f"destroyed={sid in (out.get('destroyed') or [])}")
        else:
            check("C", "unexpected sieve script", False, f"name={name} active={active}")
    final = jm.sieve_scripts()
    check("C", "sieve list as before", final == sieve_before,
          f"{len(final)} scripts (before {len(sieve_before)}), added_by_write={len(added)}")
    again = s.call_json("mail_vacation_get")
    check("C", "vacation still equal after sieve cleanup", again == prior, "")


def send_flow(s, ctx, send):
    if not send:
        skip("C", "mail_send", "no --send given; no mail sent")
        return
    to = os.environ.get("STALWART_TEST_SEND_TO", "")
    if "@" not in to:
        check("C", "mail_send", False, "STALWART_TEST_SEND_TO missing")
        return
    subject = f"stalwart-mcp e2e send {TS}"
    ok, text = s.call("mail_send", {
        "to": [to], "subject": subject,
        "body": "This is an automated stalwart-mcp end-to-end test message; safe to delete."})
    sid = parse_id(text) if ok else None
    ctx["sent"] = 1 if ok else 0
    if not check("C", "mail_send real id", ok and real_id(sid), f"id={sid}" if ok else text[:200]):
        return
    found = False
    for _ in range(6):
        if sid in ids_in(s, ctx["roles"]["sent"], 30):
            found = True
            break
        time.sleep(2)
    check("C", "sent copy in Sent", found, "listed" if found else "not listed after 12s")
    e = s.call_json("mail_get", {"id": sid})
    frm = " ".join(e.get("from", []))
    tos = [t.lower() for t in e.get("to", [])]
    check("C", "sent copy From/To/Subject",
          ctx["identity"].lower() in frm.lower() and any(to.lower() in t for t in tos)
          and len(tos) == 1 and e.get("subject") == subject and not e.get("cc"),
          f"to_count={len(tos)} (Sent copy left in place)")


def gating_flow(ctx):
    cfg = write_config(work("config-gated.toml"))
    g = Stdio(cfg, "stdio-gated")
    try:
        g.initialize()
        # Each call is invalid past the gate too, so a broken gate still writes nothing.
        for name, args in [
            ("mail_send", {"to": ["x"], "subject": "x", "body": "x"}),
            ("mail_masked_create", {"email_prefix": "_bad"}),
            ("mail_masked_disable", {"id": "e2e-nonexistent"}),
            ("mail_vacation_set", {"is_enabled": True}),
            ("spam_train", {"ids": [], "classification": "bogus"}),
            ("mail_bulk_delete", {"ids": ["e2e-nonexistent"], "permanent": True}),
        ]:
            ok, text = g.call(name, args)
            check("C", f"gated {name} disabled", is_disabled_err(ok, text), text[:120])
        for name in ["mail_list_folders", "identity_list", "mail_masked_list",
                     "mail_vacation_get", "quota_get"]:
            ok, text = g.call(name, {})
            check("C", f"gated {name} still works", ok, "ok" if ok else text[:120])
    finally:
        g.close()
        os.remove(cfg)


# ---------------------------------------------------------------- HTTP

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "stalwart-mcp-e2e", "version": "1"}}}
INITIALIZED = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()


def port_free():
    with socket.socket() as so:
        so.settimeout(1)
        return so.connect_ex(("127.0.0.1", PORT)) != 0


def http_post(path, body, token=None, host=None, session=None, want_id=None, timeout=60,
              headers=None):
    """Returns (status, headers, json_or_None, error)."""
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        conn.putrequest("POST", path, skip_host=host is not None, skip_accept_encoding=True)
        if host is not None:
            conn.putheader("Host", host)
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Accept", "application/json, text/event-stream")
        conn.putheader("Content-Length", str(len(body)))
        if token:
            conn.putheader("Authorization", f"Bearer {token}")
        if session:
            conn.putheader("Mcp-Session-Id", session)
        for name, value in headers or []:
            conn.putheader(name, value)
        conn.endheaders()
        err = None
        try:
            conn.send(body)
        except (BrokenPipeError, ConnectionResetError) as e:
            err = f"send: {type(e).__name__}"
        try:
            resp = conn.getresponse()
        except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected) as e:
            return None, {}, None, err or type(e).__name__
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        if resp.status != 200 or want_id is None:
            resp.read(4096)
            return resp.status, hdrs, None, err
        if "text/event-stream" in hdrs.get("content-type", ""):
            buf = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                buf += chunk
                for line in buf.split(b"\n"):
                    if line.startswith(b"data:"):
                        try:
                            msg = json.loads(line[5:].strip())
                        except ValueError:
                            continue
                        if msg.get("id") == want_id:
                            return resp.status, hdrs, msg, err
            return resp.status, hdrs, None, "no matching SSE event"
        return resp.status, hdrs, json.loads(resp.read() or b"null"), err
    finally:
        conn.close()


def http_tool_call(token, name, args):
    """Open a fresh session with `token` and call one tool. Returns (ok, text)."""
    st, h, _, e = http_post("/mcp", json.dumps(INIT).encode(), token=token, want_id=1)
    sess = h.get("mcp-session-id")
    if st != 200 or not sess:
        return False, f"initialize status={st} session={bool(sess)} {e or ''}"
    http_post("/mcp", INITIALIZED, token=token, session=sess)
    call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": name, "arguments": args}}
    st, _, msg, e = http_post("/mcp", json.dumps(call).encode(), token=token,
                              session=sess, want_id=3)
    if st != 200:
        return False, f"tools/call status={st} {e or ''}"
    return tool_result(msg)


def token_create(cfg, scopes, account="*"):
    """Create a 1-day token; the token itself is never printed."""
    r = subprocess.run([BIN, "-c", cfg, "token", "create", "--scopes", scopes,
                        "--account", account, "--expires", "1"],
                       capture_output=True, text=True, timeout=30)
    token = r.stdout.strip()
    return token if r.returncode == 0 and token.count(".") == 2 else None


def start_http(cfg, label):
    log, logf = open_log(label)
    p = subprocess.Popen([BIN, "-c", cfg, "serve", "--bind", ADDR],
                         stdin=subprocess.DEVNULL, stdout=logf, stderr=logf, env=os.environ)
    deadline = time.time() + 45
    while time.time() < deadline:
        if p.poll() is not None:
            logf.close()
            raise RuntimeError(f"{label} exited {p.returncode}: {log_tail(log)}")
        if not port_free():
            return p, logf, log
        time.sleep(0.3)
    stop_http(p, logf)
    raise RuntimeError(f"{label} did not listen within 45s")


def stop_http(p, logf):
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(5)
    logf.close()


def http_scope_checks():
    """Scope and account restriction over HTTP. Every refused call uses input that
    also fails validation, so even a broken check could not create anything."""
    cfg = work("config-http-secret.toml")
    read_only = token_create(cfg, "mail:read")
    other = token_create(cfg, "*", OTHER_ACCOUNT)
    own = token_create(cfg, "*", ACCOUNT)
    if not check("D", "scoped tokens created", read_only and other and own, ""):
        return

    ok, text = http_tool_call(read_only, "mail_list_folders", {})
    check("D", "read-only token: mail_list_folders allowed", ok, "ok" if ok else text[:120])
    ok, text = http_tool_call(read_only, "mail_draft", {"to": "not-a-list"})
    check("D", "read-only token: mail_draft refused",
          not ok and "Forbidden" in text and "mail:modify" in text, text[:120])

    ok, text = http_tool_call(other, "mail_list_folders", {"account": ACCOUNT})
    check("D", "account-restricted token: other account refused",
          not ok and "Forbidden" in text and "another account" in text, text[:120])
    ok, text = http_tool_call(other, "mail_draft", {"account": ACCOUNT, "to": "not-a-list"})
    check("D", "account-restricted token: write on other account refused",
          not ok and "Forbidden" in text, text[:120])
    ok, text = http_tool_call(own, "mail_list_folders", {})
    check("D", "account-restricted token: own account by default", ok,
          "ok" if ok else text[:120])


def section_d(ctx):
    if not check("D", "port free before", port_free(), ADDR):
        return
    init = json.dumps(INIT).encode()
    secret = secrets.token_urlsafe(32)
    cfg = write_config(work("config-http-secret.toml"), secret=secret)
    try:
        token = token_create(cfg, "*")
        check("D", "token create", token is not None, "")
        p, logf, _ = start_http(cfg, "http-secret")
        try:
            st, _, _, e = http_post("/mcp", init)
            check("D", "POST /mcp no token = 401", st == 401, f"status={st} {e or ''}")
            st, _, _, e = http_post("/nope", init)
            check("D", "POST /nope no token = 401", st == 401, f"status={st} {e or ''}")

            st, h, msg, e = http_post("/mcp", init, token=token, want_id=1)
            si = (msg or {}).get("result", {}).get("serverInfo", {})
            sess = h.get("mcp-session-id")
            check("D", "initialize with JWT", st == 200 and si.get("name") == "stalwart-mcp"
                  and si.get("version") == VERSION,
                  f"status={st} server={si.get('name')} {si.get('version')} session={bool(sess)} {e or ''}")
            st2, _, _, _ = http_post("/mcp", INITIALIZED, token=token, session=sess)
            st, _, msg, e = http_post("/mcp", json.dumps(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode(),
                token=token, session=sess, want_id=2)
            n = len((msg or {}).get("result", {}).get("tools", []))
            check("D", "tools/list with JWT", st == 200 and n == ctx.get("tool_count", 19),
                  f"status={st} tools={n} initialized_status={st2} {e or ''}")

            if token:
                h_, p_, sig = token.split(".")
                i = len(sig) // 2
                sig = sig[:i] + ("A" if sig[i] != "A" else "B") + sig[i + 1:]
                st, _, _, e = http_post("/mcp", init, token=f"{h_}.{p_}.{sig}")
                check("D", "tampered token = 401", st == 401, f"status={st} {e or ''}")

            st, _, _, e = http_post("/mcp", init, token=token, host="evil.example.com")
            check("D", "Host evil.example.com rejected", st is not None and 400 <= st < 500
                  and st != 401, f"status={st} {e or ''}")

            st, _, _, e = http_post("/mcp", init, token=token,
                                    headers=[("X-Forwarded-For", "198.51.100.7")])
            check("D", "with secret: forwarded request with JWT accepted", st == 200,
                  f"status={st} {e or ''}")

            big = json.dumps({**INIT, "params": {**INIT["params"],
                                                  "pad": "x" * (2 * 1024 * 1024 + 4096)}}).encode()
            st, _, _, e = http_post("/mcp", big, token=token)
            check("D", "body > 2 MB = 413", st == 413, f"status={st} bytes={len(big)} {e or ''}")

            http_scope_checks()
        finally:
            stop_http(p, logf)
            time.sleep(0.5)
            check("D", "port free after secret server", port_free(), "")
    finally:
        os.remove(cfg)

    cfg = write_config(work("config-http-guard.toml"), allowed_hosts=["mcp.example.com"])
    try:
        try:
            r = subprocess.run([BIN, "-c", cfg, "serve", "--bind", ADDR],
                               capture_output=True, text=True, timeout=30,
                               stdin=subprocess.DEVNULL)
            msg = r.stderr
            check("D", "guard: allowed_hosts without secret exits",
                  r.returncode != 0 and "server.allowed_hosts" in msg and "auth.secret" in msg,
                  f"rc={r.returncode} names_both={'server.allowed_hosts' in msg and 'auth.secret' in msg}")
        except subprocess.TimeoutExpired:
            check("D", "guard: allowed_hosts without secret exits", False,
                  "still running after 30s (killed)")
    finally:
        os.remove(cfg)
        check("D", "port free after guard", port_free(), "")

    cfg = write_config(work("config-http-open.toml"))
    try:
        p, logf, _ = start_http(cfg, "http-open")
        try:
            st, _, msg, e = http_post("/mcp", init, want_id=1)
            si = (msg or {}).get("result", {}).get("serverInfo", {})
            check("D", "no secret: loopback without token accepted",
                  st == 200 and si.get("name") == "stalwart-mcp", f"status={st} {e or ''}")
            for hdrs in [[("X-Forwarded-For", "198.51.100.7")],
                         [("forwarded", "for=198.51.100.7")],
                         [("X-REAL-IP", "198.51.100.7")],
                         [("X-Forwarded-Proto", "https")],
                         [("Via", "1.1 proxy")],
                         [("X-Forwarded-For", "127.0.0.1"), ("x-forwarded-for", "198.51.100.7")]]:
                st, _, _, e = http_post("/mcp", init, headers=hdrs)
                check("D", f"no secret: forwarded {[n for n, _ in hdrs]} = 401", st == 401,
                      f"status={st} {e or ''}")
        finally:
            stop_http(p, logf)
            time.sleep(0.5)
            check("D", "port free after open server", port_free(), "")
    finally:
        os.remove(cfg)


# ---------------------------------------------------------------- leftovers

def leftovers(s, ctx, jm):
    roles = ctx["roles"]
    tag = f"e2e draft {TS}"
    hits = 0
    for role in ["drafts", "trash"]:
        for e in ids_in(s, roles[role], 100).values():
            if tag in (e.get("subject") or ""):
                hits += 1
    check("E", "no e2e draft/trash item from this run", hits == 0, f"{hits} found")
    if "draft_id" in ctx:
        check("E", "own draft gone", jm.email_subject(ctx["draft_id"]) is None, "")
    m = s.call_json("mail_masked_list")
    check("E", "masked count as before", len(m) == ctx["masked_before"],
          f"{len(m)} (before {ctx['masked_before']})")
    v = s.call_json("mail_vacation_get")
    check("E", "vacation as before", v == ctx["vacation_before"], "")
    if "sieve_before" in ctx:
        check("E", "sieve list as before", jm.sieve_scripts() == ctx["sieve_before"], "")


# ---------------------------------------------------------------- main

def run(args, ctx):
    cfg = write_config(work("config.toml"), send=True, masked=True, vacation=True)
    s = Stdio(cfg, "stdio-main")
    _S["main"] = s
    try:
        for label, fn in [("A", lambda: section_a(s, ctx)), ("B", lambda: section_b(s, ctx))]:
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                check(label, "section aborted", False, f"{type(e).__name__}: {e}")
        # Every write flow cleans up over direct JMAP, so without a working JMAP
        # session nothing is created at all.
        jm = None
        try:
            jm = Jmap(ctx["account_id"])
            check("C", "direct JMAP session", True, "")
        except Exception as e:  # noqa: BLE001
            check("C", "direct JMAP session", False,
                  f"{type(e).__name__}: {e}; draft, masked and vacation writes skipped")
        flows = [
            ("send", lambda: send_flow(s, ctx, args.send)),
            ("gating", lambda: gating_flow(ctx)),
        ]
        if jm is not None:
            flows = [
                ("draft", lambda: draft_flow(s, ctx, jm)),
                ("masked", lambda: masked_flow(s, ctx, jm)),
                ("vacation", lambda: vacation_flow(s, ctx, jm)),
            ] + flows
        for name, fn in flows:
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                check("C", f"{name} aborted", False, f"{type(e).__name__}: {e}")
        ok, text = s.call("spam_train", {"ids": [], "classification": "bogus"})
        check("C", "spam_train disabled (spam_training=false)", is_disabled_err(ok, text), text[:120])
        try:
            section_d(ctx)
        except Exception as e:  # noqa: BLE001
            check("D", "section aborted", False, f"{type(e).__name__}: {e}")
        try:
            leftovers(s, ctx, jm)
        except Exception as e:  # noqa: BLE001
            check("E", "leftover check aborted", False, f"{type(e).__name__}: {e}")
    finally:
        s.close()
    return ctx


def main():
    global BIN, PORT, ADDR, WORKDIR
    ap = argparse.ArgumentParser(description="stalwart-mcp end-to-end test (live server)")
    ap.add_argument("--send", action="store_true",
                    help="send one real message to STALWART_TEST_SEND_TO (default: no mail)")
    ap.add_argument("--bin", default=os.path.expanduser("~/.cargo/bin/stalwart-mcp"),
                    help="stalwart-mcp binary to test")
    ap.add_argument("--port", type=int, default=38766, help="loopback port for HTTP checks")
    ap.add_argument("--keep-logs", action="store_true",
                    help="keep the temporary directory with server logs")
    args = ap.parse_args()
    for var in ["STALWART_TEST_URL", "STALWART_TEST_USER", "STALWART_PASSWORD"]:
        if not os.environ.get(var):
            print(f"FAIL env: {var} not set")
            return 2
    if args.send and "@" not in os.environ.get("STALWART_TEST_SEND_TO", ""):
        print("FAIL env: --send needs STALWART_TEST_SEND_TO")
        return 2
    BIN, PORT = args.bin, args.port
    ADDR = f"127.0.0.1:{PORT}"
    WORKDIR = tempfile.mkdtemp(prefix="stalwart-mcp-e2e-")  # mode 0700
    info(f"run {TS}, version {VERSION}, send={args.send}")
    ctx = {"sent": 0}
    try:
        run(args, ctx)
    except BaseException as e:  # noqa: BLE001 - always clean up and print the summary
        check("Z", "run aborted", False, f"{type(e).__name__}: {e}")
    finally:
        if args.keep_logs:
            info(f"logs kept in {WORKDIR}")
        else:
            shutil.rmtree(WORKDIR, ignore_errors=True)
            cleanup("temporary config and log directory removed")
    total_fail = sum(v[1] for v in RESULTS.values())
    print("SUMMARY " + " ".join(f"{k}:{v[0]}pass/{v[1]}fail" for k, v in sorted(RESULTS.items()))
          + f" emails_sent_this_run={ctx['sent']}", flush=True)
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
