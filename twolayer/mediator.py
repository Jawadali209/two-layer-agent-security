"""Two-layer mediator: combines Layer 1 rules and the Layer 2 detector and writes a decision record (Objective 6).

Configurations (Objective 7, offline):
  none    - every call is allowed (undefended agent)
  layer1  - Layer 1 rules only
  layer2  - Layer 2 detector only (alert -> simulated confirmation -> refusal)
  both    - Layer 1 first; a call that passes Layer 1 is then scored by Layer 2
"""
import json
import time

import pandas as pd

from .features import call_features, FEATURES
from .layer1 import RuleEngine

CONFIGS = ['none', 'layer1', 'layer2', 'both']


class TwoLayerMediator:
    def __init__(self, detector=None, config: str = 'both', explain: bool = True, engines: dict | None = None):
        assert config in CONFIGS, config
        self.detector = detector
        self.config = config
        self.explain = explain
        self.engines = engines or {}

    def engine(self, suite):
        if suite not in self.engines:
            self.engines[suite] = RuleEngine(suite)
        return self.engines[suite]

    def decide(self, suite: str, request: str, prev_tools: list, tool: str, args: dict) -> dict:
        """Decision record for one proposed call."""
        t0 = time.perf_counter()
        rec = {'suite': suite, 'tool': tool, 'args': json.loads(json.dumps(args, default=str)),
               'layer1': None, 'layer2': None, 'decision': 'allow', 'decided_by': None}
        use_l1 = self.config in ('layer1', 'both')
        use_l2 = self.config in ('layer2', 'both') and self.detector is not None
        if use_l1:
            d, rule, reason = self.engine(suite).check(tool, args, request, prev_tools)
            rec['layer1'] = {'decision': d, 'rule': rule, 'reason': reason}
            if d != 'allow':
                rec['decision'], rec['decided_by'] = d, 'layer1'
        t1 = time.perf_counter()
        if use_l2 and rec['decision'] == 'allow':
            x = pd.DataFrame([call_features(suite, request, prev_tools, tool, args)])[FEATURES].astype(float)
            score = float(self.detector.score(x)[0])
            alert = score > self.detector.threshold
            rec['layer2'] = {'score': round(score, 4), 'threshold': round(self.detector.threshold, 4), 'alert': bool(alert)}
            t2 = time.perf_counter()
            if alert:
                rec['decision'], rec['decided_by'] = 'confirm', 'layer2'
                if self.explain:
                    rec['layer2']['top_features'] = self.detector.top_features(x.iloc[0])
        else:
            t2 = time.perf_counter()
        t3 = time.perf_counter()
        rec['time_ms'] = {'layer1': round((t1 - t0) * 1000, 3), 'layer2_score': round((t2 - t1) * 1000, 3),
                          'shap_explanation': round((t3 - t2) * 1000, 3)}
        return rec
