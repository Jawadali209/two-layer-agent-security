"""Task-disjoint partitions (Objective 4).

Within workspace, travel and banking, user tasks are split 50 / 20 / 30 into train / validation / test
with a fixed seed, so that no user task appears in more than one partition. Slack is held out completely
for the generalisation tests (SRQ2).
"""
import numpy as np
import pandas as pd

HELD_OUT_SUITE = 'slack'
FRACTIONS = {'train': 0.5, 'val': 0.2}      # the rest is test
SEED = 42


def make_partitions(runs: pd.DataFrame, seed: int = SEED) -> pd.DataFrame:
    rows = []
    rng = np.random.RandomState(seed)
    for suite in sorted(runs.suite.unique()):
        tasks = sorted(runs[(runs.suite == suite) & (runs.kind == 'benign')].user_task.unique(),
                       key=lambda t: int(t.split('_')[-1]))
        if suite == HELD_OUT_SUITE:
            rows += [dict(suite=suite, user_task=t, split='heldout_env') for t in tasks]
            continue
        order = rng.permutation(len(tasks))
        n_tr = int(round(FRACTIONS['train'] * len(tasks)))
        n_va = int(round(FRACTIONS['val'] * len(tasks)))
        for rank, i in enumerate(order):
            split = 'train' if rank < n_tr else ('val' if rank < n_tr + n_va else 'test')
            rows.append(dict(suite=suite, user_task=tasks[i], split=split))
    return pd.DataFrame(rows)


def attach_split(df: pd.DataFrame, parts: pd.DataFrame) -> pd.DataFrame:
    m = parts.set_index(['suite', 'user_task'])['split']
    df = df.copy()
    df['split'] = [m.get((s, t), 'none') for s, t in zip(df.suite, df.user_task)]
    return df
