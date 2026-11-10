"""Environment-neutral features for each proposed tool call (Objective 4).

Every feature is computed only from what a mediator sees before the call runs: the user's request,
the calls made so far (with their categories) and the proposed call itself.
"""
import json
import math
import re

import numpy as np
import pandas as pd

from .catalog import CATEGORIES, SIDE_EFFECT_CATEGORIES, UNTRUSTED_CATEGORIES, ACTION_WORDS, tool_info

_EMAIL = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')
_IBAN = re.compile(r'\b[A-Z]{2}\d{10,32}\b')
_URL = re.compile(r'(?:https?://|www\.)[\w.-]+', re.I)

FEATURE_GROUPS = {
    'tool_category': [f'cat_{c}' for c in CATEGORIES],
    'sequence': [f'prev1_{c}' for c in CATEGORIES + ['start']] + [f'prev2_{c}' for c in CATEGORIES + ['start']]
                + ['call_idx', 'repeat_tool'],
    'provenance': ['n_targets', 'new_target', 'has_url', 'has_email', 'has_iban'],
    'context': ['n_untrusted_before', 'untrusted_before', 'side_effect', 'side_effect_after_untrusted'],
    'request_alignment': ['unrequested_action'],
    'argument_shape': ['n_args', 'log_arg_chars', 'log_amount'],
}
FEATURES = [f for g in FEATURE_GROUPS.values() for f in g]


def target_values(suite: str, tool: str, args: dict):
    """Recipient / account / e-mail / user / URL values in the call's target arguments."""
    vals = []
    for name in tool_info(suite, tool)['targets']:
        v = args.get(name)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            vals += [str(x) for x in v if x not in (None, '')]
        elif v != '':
            vals.append(str(v))
    return vals


def requested(category: str, request: str) -> bool:
    """True if the user's request contains a word for this kind of action."""
    if category not in ACTION_WORDS:
        return True                      # plain reads are always within a request
    r = request.lower()
    return any(re.search(r'\b' + re.escape(w), r) for w in ACTION_WORDS[category])


def call_features(suite: str, request: str, prev_tools: list, tool: str, args: dict) -> dict:
    """Features of one proposed call, given the tools already called in this run (in order)."""
    req = request.lower()
    cat = tool_info(suite, tool)['category']
    prev_cats = [tool_info(suite, t)['category'] for t in prev_tools]
    p1 = prev_cats[-1] if len(prev_cats) >= 1 else 'start'
    p2 = prev_cats[-2] if len(prev_cats) >= 2 else 'start'
    n_untrusted = sum(c in UNTRUSTED_CATEGORIES for c in prev_cats)
    targets = target_values(suite, tool, args)
    new_t = [t for t in targets if t.strip().lower() not in req]
    blob = json.dumps(args, ensure_ascii=False)
    amount = args.get('amount')
    try:
        amount = abs(float(amount)) if amount is not None else 0.0
    except (TypeError, ValueError):
        amount = 0.0
    side = cat in SIDE_EFFECT_CATEGORIES
    f = {f'cat_{c}': int(cat == c) for c in CATEGORIES}
    f.update({f'prev1_{c}': int(p1 == c) for c in CATEGORIES + ['start']})
    f.update({f'prev2_{c}': int(p2 == c) for c in CATEGORIES + ['start']})
    f.update(call_idx=len(prev_tools), repeat_tool=sum(t == tool for t in prev_tools),
             n_targets=len(targets), new_target=int(len(new_t) > 0),
             has_url=int(bool(_URL.search(blob))), has_email=int(bool(_EMAIL.search(blob))),
             has_iban=int(bool(_IBAN.search(blob))),
             n_untrusted_before=n_untrusted, untrusted_before=int(n_untrusted > 0),
             side_effect=int(side), side_effect_after_untrusted=int(side and n_untrusted > 0),
             unrequested_action=int((side or cat == 'read_web') and not requested(cat, request)),
             n_args=len([v for v in args.values() if v not in (None, '', [])]),
             log_arg_chars=math.log1p(len(blob)), log_amount=math.log1p(amount))
    return f


def build_features(calls: pd.DataFrame, runs: pd.DataFrame) -> pd.DataFrame:
    """Feature matrix aligned with `calls` (same index)."""
    req = runs.set_index('run_id')['request']
    out = []
    for run_id, g in calls.groupby('run_id', sort=False):
        prev = []
        for r in g.sort_values('call_idx').itertuples():
            f = call_features(r.suite, req[run_id], prev, r.tool, json.loads(r.args))
            f['_index'] = r.Index
            out.append(f)
            prev.append(r.tool)
    X = pd.DataFrame(out).set_index('_index').loc[calls.index]
    return X[FEATURES].astype(float)
