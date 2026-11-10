"""n-gram baseline in the style of Forrest et al. (1996).

The 'normal database' holds every sequence of up to N consecutive tool categories seen in the benign training
runs (with a START symbol at the beginning of each run). A proposed call is scored by how many of the windows that
end with it (lengths 1..N) are missing from the database, so the score is 0 (all seen) to N (nothing seen).
Tool categories are used instead of raw tool names so that the baseline, like Layer 2, can be applied to the
held-out environment. The threshold is set with the same 5% false-alarm rule on validation benign calls.
"""
import numpy as np

from .catalog import tool_info
from .layer2 import far_threshold, TARGET_FAR


class NgramDetector:
    def __init__(self, n: int = 3):
        self.n = n
        self.db = set()
        self.threshold = None

    def _symbols(self, suite, tools):
        return ['START'] + [tool_info(suite, t)['category'] for t in tools]

    def fit(self, sequences):
        """sequences: iterable of (suite, [tool names in order]) from benign training runs."""
        for suite, tools in sequences:
            sym = self._symbols(suite, tools)
            for end in range(1, len(sym)):
                for L in range(1, self.n + 1):
                    if end - L + 1 >= 0:
                        self.db.add(tuple(sym[end - L + 1:end + 1]))
        return self

    def score_call(self, suite, prev_tools, tool) -> int:
        sym = self._symbols(suite, list(prev_tools) + [tool])
        end = len(sym) - 1
        return sum(tuple(sym[end - L + 1:end + 1]) not in self.db for L in range(1, self.n + 1) if end - L + 1 >= 0)

    def score_runs(self, calls_df):
        """Score every call of a calls DataFrame (needs columns run_id, suite, call_idx, tool). Returns aligned array."""
        out = {}
        for _, g in calls_df.groupby('run_id', sort=False):
            g = g.sort_values('call_idx')
            prev = []
            for r in g.itertuples():
                out[r.Index] = self.score_call(r.suite, prev, r.tool)
                prev.append(r.tool)
        return np.array([out[i] for i in calls_df.index], dtype=float)

    def calibrate(self, benign_scores, far: float = TARGET_FAR):
        self.threshold = far_threshold(benign_scores, far)
        return self.threshold
