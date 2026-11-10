"""Layer 1: deterministic rule-based tool-call mediator (Objective 5).

Rules are read from one YAML file per environment (twolayer/rules/<suite>.yaml). Each rule names the tools it
applies to, a check, and an action ('block' or 'confirm'). Rules are evaluated in order and the first rule that a
proposed call breaks decides the outcome. Offline there is no human, so 'confirm' is simulated as a refusal.
"""
import os
import re

import yaml

from .catalog import SIDE_EFFECT_CATEGORIES, UNTRUSTED_CATEGORIES, tool_info
from .features import requested, target_values

RULE_DIR = os.path.join(os.path.dirname(__file__), 'rules')
_URL = re.compile(r'(?:https?://)?(?:www\.)[\w.-]+(?:/[\w./?=&%-]*)?', re.I)


# ----------------------------------------------------------------------------- trusted data from the initial environment
def _env(suite: str):
    from agentdojo.task_suite.load_suites import get_suite
    return get_suite('v1', suite).load_and_inject_default_environment({})


def banking_payees():
    acc = _env('banking').bank_account
    vals = {acc.iban}
    for t in list(acc.transactions) + list(acc.scheduled_transactions):
        vals.update([t.recipient, t.sender])
    return sorted(v for v in vals if v and v != 'me')


def workspace_contacts():
    inbox = _env('workspace').inbox
    return sorted({c.email for c in inbox.contact_list} | {inbox.account_email})


def workspace_calendar_participants():
    cal = _env('workspace').calendar
    return sorted({p for e in cal.events.values() for p in e.participants})


def travel_user_email():
    return [_env('travel').user.email]


def slack_users():
    return list(_env('slack').slack.users)


def slack_channels():
    return list(_env('slack').slack.channels)


EXTRACTORS = {f.__name__: f for f in [banking_payees, workspace_contacts, workspace_calendar_participants,
                                      travel_user_email, slack_users, slack_channels]}


# ----------------------------------------------------------------------------- rule engine
class RuleEngine:
    def __init__(self, suite: str, rule_dir: str = RULE_DIR):
        self.suite = suite
        with open(os.path.join(rule_dir, f'{suite}.yaml'), encoding='utf8') as fh:
            self.spec = yaml.safe_load(fh)
        self.rules = self.spec['rules']
        self.allowed_tools = self.spec.get('allowed_tools', '*')
        self.trusted = {name: {v.strip().lower() for v in EXTRACTORS[fn]()}
                        for name, fn in (self.spec.get('trusted_sets') or {}).items()}

    def _applies(self, rule, tool):
        t = rule['tools']
        cat = tool_info(self.suite, tool)['category']
        if t == '*':
            return True
        if t == '*side_effect*':
            return cat in SIDE_EFFECT_CATEGORIES
        if t == '*side_effect_or_web*':
            return cat in SIDE_EFFECT_CATEGORIES or cat == 'read_web'
        return tool in t

    def _in_allowlist(self, value, sources, request):
        v = str(value).strip().lower()
        for s in sources:
            if s == 'request':
                if v and v in request.lower():
                    return True
            elif v in self.trusted.get(s, set()):
                return True
        return False

    def _violates(self, rule, tool, args, request, prev_tools):
        check = rule['check']
        if check == 'targets_in_allowlist':
            vals = []
            for a in rule['args']:
                v = args.get(a)
                if v is None or v == '':
                    continue
                vals += [x for x in (v if isinstance(v, (list, tuple)) else [v]) if x not in (None, '')]
            bad = [x for x in vals if not self._in_allowlist(x, rule['allowlist'], request)]
            return (f'not allowed: {", ".join(map(str, bad))}' if bad else None)
        if check == 'max_amount':
            try:
                amt = abs(float(args.get(rule['arg'], 0) or 0))
            except (TypeError, ValueError):
                return None
            return f'amount {amt:g} > limit {rule["limit"]}' if amt > rule['limit'] else None
        if check == 'request_mentions':
            r = request.lower()
            return None if any(re.search(r'\b' + re.escape(w), r) for w in rule['words']) else 'not requested by the user'
        if check == 'unrequested_after_untrusted':
            untrusted = any(tool_info(self.suite, t)['category'] in UNTRUSTED_CATEGORIES for t in prev_tools)
            cat = tool_info(self.suite, tool)['category']
            if untrusted and not requested(cat, request):
                return f'{cat} action not in the request, after untrusted content'
            return None
        if check == 'no_new_urls':
            urls = []
            for a in rule['args']:
                urls += _URL.findall(str(args.get(a) or ''))
            bad = [u for u in urls if u.lower().rstrip('/.') not in request.lower()]
            return f'link not from the user: {", ".join(bad)}' if bad else None
        raise ValueError(f'unknown check {check}')

    def check(self, tool: str, args: dict, request: str, prev_tools: list):
        """Return (decision, rule_id, reason) with decision in {'allow', 'block', 'confirm'}."""
        if self.allowed_tools != '*' and tool not in self.allowed_tools:
            return 'block', 'TOOLS', f'tool {tool} is not permitted'
        for rule in self.rules:
            if not self._applies(rule, tool):
                continue
            reason = self._violates(rule, tool, args, request, prev_tools)
            if reason:
                return rule['action'], rule['id'], reason
        return 'allow', None, None
