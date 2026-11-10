"""Evaluation helpers for Objectives 7-9 (offline)."""
import contextlib
import io
import itertools
import json

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.metrics import roc_auc_score

from .agentdojo_bridge import replay_run
from .features import FEATURE_GROUPS, FEATURES
from .layer2 import AnomalyDetector
from .mediator import TwoLayerMediator


# ----------------------------------------------------------------------------- call level (recorded traces)
def layer1_flags(ev: pd.DataFrame, engines: dict, requests: pd.Series) -> pd.DataFrame:
    """Layer 1 decision for every recorded call, given the recorded history of its run."""
    out = []
    for rid, g in ev.groupby('run_id', sort=False):
        prev = []
        for r in g.sort_values('call_idx').itertuples():
            d, rule, why = engines[r.suite].check(r.tool, json.loads(r.args), requests[rid], prev)
            out.append((r.Index, d, rule))
            prev.append(r.tool)
    return pd.DataFrame(out, columns=['i', 'l1_decision', 'l1_rule']).set_index('i')


def call_metrics(y_true, flag, score=None, benign_run=None) -> dict:
    """Precision, recall, F1, false-alarm rate and ROC-AUC at call level.

    y_true: harmful label; flag: refused/alerted; score: continuous score for ROC-AUC (optional);
    benign_run: boolean mask of calls from benign runs (the false-alarm rate is computed on these)."""
    y = np.asarray(y_true, bool); f = np.asarray(flag, bool)
    tp, fp, fn = int((y & f).sum()), int((~y & f).sum()), int((y & ~f).sum())
    prec = tp / (tp + fp) if tp + fp else np.nan
    rec = tp / (tp + fn) if tp + fn else np.nan
    f1 = 2 * prec * rec / (prec + rec) if prec and rec and not np.isnan(prec + rec) else 0.0
    br = np.asarray(benign_run, bool) if benign_run is not None else ~y
    far = f[br].mean() if br.any() else np.nan
    auc = roc_auc_score(y, score) if score is not None and 0 < y.sum() < len(y) else np.nan
    return dict(harmful=int(y.sum()), flagged=int(f.sum()), TP=tp, FP=fp, precision=prec, recall=rec, F1=f1,
                false_alarm_rate=far, fpr_all_negatives=(fp / (~y).sum() if (~y).sum() else np.nan), roc_auc=auc)


def bootstrap_ci(df: pd.DataFrame, fn, n: int = 1000, seed: int = 0, level: float = 0.95):
    """Run-level (cluster) bootstrap confidence interval for a metric fn(df)."""
    rng = np.random.RandomState(seed)
    runs = df.run_id.unique()
    groups = {r: g for r, g in df.groupby('run_id')}
    vals = []
    for _ in range(n):
        pick = rng.choice(runs, len(runs), replace=True)
        v = fn(pd.concat([groups[r] for r in pick], ignore_index=True))
        if v is not None and not np.isnan(v):
            vals.append(v)
    lo, hi = np.percentile(vals, [(1 - level) / 2 * 100, (1 + level) / 2 * 100]) if vals else (np.nan, np.nan)
    return float(lo), float(hi)


def detection_delay(ev: pd.DataFrame, flag_col: str) -> pd.DataFrame:
    """For every attacked run with a harmful call: was the first refusal at or before the first harmful call,
    and how many calls after the agent first read the injected text did the first refusal come?"""
    rows = []
    for rid, g in ev[ev.kind == 'attacked'].groupby('run_id'):
        g = g.sort_values('call_idx')
        if not g.harmful.any():
            continue
        first_harm = int(g[g.harmful].call_idx.min())
        exposed = g[g.injection_seen_before]
        exposure = int(exposed.call_idx.min()) if len(exposed) else None
        flagged = g[g[flag_col]]
        first_flag = int(flagged.call_idx.min()) if len(flagged) else None
        rows.append(dict(run_id=rid, first_harm=first_harm, exposure=exposure, first_flag=first_flag,
                         stopped_before_harm=(first_flag is not None and first_flag <= first_harm),
                         delay_after_exposure=(first_flag - exposure if first_flag is not None and exposure is not None
                                               else np.nan)))
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- run level (replay in AgentDojo)
def replay_runs(df_runs, raw, suites, config, detector=None, engines=None, explain=False):
    m = TwoLayerMediator(detector=detector, config=config, engines=engines, explain=explain)
    res, recs = [], []
    for r in df_runs.itertuples():
        with contextlib.redirect_stdout(io.StringIO()):
            u, s, rr = replay_run(suites[r.suite], r.suite, raw[r.run_id], m, r.run_id)
        res.append(dict(run_id=r.run_id, suite=r.suite, kind=r.kind, split=r.split, injection_task=r.injection_task,
                        utility=u, security=s, refused=any(x['decision'] != 'allow' for x in rr)))
        recs += rr
    return pd.DataFrame(res), recs


def run_summary(res: pd.DataFrame) -> dict:
    b, a = res[res.kind == 'benign'], res[res.kind == 'attacked']
    return {'benign_utility_%': b.utility.mean() * 100, 'utility_under_attack_%': a.utility.mean() * 100,
            'attack_success_rate_%': a.security.mean() * 100, 'benign_runs_with_refusal_%': b.refused.mean() * 100,
            'benign_runs': len(b), 'attacked_runs': len(a)}


# ----------------------------------------------------------------------------- detector training helpers
def train_detector(X, m_train, m_val, seed=0, features=None):
    det = AnomalyDetector(seed=seed, features=features).fit(X[m_train])
    det.calibrate(X[m_val])
    return det


def global_importance(det: AnomalyDetector, X: pd.DataFrame) -> pd.Series:
    """Mean absolute SHAP contribution of each feature over the given calls."""
    return det.anomaly_contributions(X).abs().mean().sort_values(ascending=False)


def group_importance(imp: pd.Series) -> pd.Series:
    return pd.Series({g: imp.reindex(cols).fillna(0).sum() for g, cols in FEATURE_GROUPS.items()}).sort_values(ascending=False)


def ablation(X, ev, m_train, m_val, eval_masks: dict, seeds=range(5)) -> pd.DataFrame:
    """Retrain the detector without each feature group in turn; report ROC-AUC, recall and false-alarm rate."""
    rows = []
    variants = {'all features': FEATURES}
    variants.update({f'without {g}': [f for f in FEATURES if f not in cols] for g, cols in FEATURE_GROUPS.items()})
    for name, feats in variants.items():
        for seed in seeds:
            det = train_detector(X, m_train, m_val, seed=seed, features=feats)
            for split, m in eval_masks.items():
                sub = ev[m]
                s = det.score(X.loc[sub.index])
                met = call_metrics(sub.harmful, s > det.threshold, s, sub.kind == 'benign')
                rows.append(dict(variant=name, seed=seed, split=split, roc_auc=met['roc_auc'], recall=met['recall'],
                                 false_alarm_rate=met['false_alarm_rate']))
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- explanation reliability (Objective 9)
def jaccard(a, b):
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if a | b else 1.0


def seed_stability(X, m_train, m_val, X_explain: pd.DataFrame, alert_index, seeds=range(10), k=3):
    """Retrain with several seeds; compare global rankings and the top-k features of the same alerts."""
    dets, imps, tops = {}, {}, {}
    for seed in seeds:
        det = train_detector(X, m_train, m_val, seed=seed)
        contrib = det.anomaly_contributions(X_explain)
        dets[seed] = det
        imps[seed] = contrib.abs().mean()
        tops[seed] = {i: list(contrib.loc[i].sort_values(ascending=False).head(k).index) for i in alert_index}
    pairs = list(itertools.combinations(list(seeds), 2))
    rank_corr = [spearmanr(imps[a][FEATURES], imps[b][FEATURES]).correlation for a, b in pairs]
    top5 = [jaccard(imps[a].sort_values(ascending=False).head(5).index, imps[b].sort_values(ascending=False).head(5).index)
            for a, b in pairs]
    per_alert = []
    for i in alert_index:
        per_alert.append(dict(index=i,
                              top1_agreement=np.mean([tops[s][i][0] == tops[0][i][0] for s in seeds if s != 0]),
                              topk_jaccard=np.mean([jaccard(tops[s][i], tops[0][i]) for s in seeds if s != 0])))
    return dets, imps, pd.DataFrame(per_alert), dict(spearman_mean=float(np.mean(rank_corr)),
                                                      spearman_min=float(np.min(rank_corr)),
                                                      top5_jaccard_mean=float(np.mean(top5)))


def removal_test(det: AnomalyDetector, X_alerts: pd.DataFrame, k_values=(1, 3), n_random=20, seed=0) -> pd.DataFrame:
    """Replace the top-k SHAP features of each alert with their benign (training) median and re-score.
    A control replaces k randomly chosen other features instead."""
    rng = np.random.RandomState(seed)
    contrib = det.anomaly_contributions(X_alerts)
    base = det.score(X_alerts)
    rows = []
    for j, i in enumerate(X_alerts.index):
        order = list(contrib.loc[i].sort_values(ascending=False).index)
        for k in k_values:
            x = X_alerts.loc[[i]].copy(); x[order[:k]] = det.benign_median[order[:k]].values
            s_top = det.score(x)[0]
            ctrl = []
            for _ in range(n_random):
                cols = list(rng.choice(order[k:], k, replace=False))
                xr = X_alerts.loc[[i]].copy(); xr[cols] = det.benign_median[cols].values
                ctrl.append(det.score(xr)[0])
            rows.append(dict(index=i, k=k, score=base[j], score_top_removed=s_top, score_random_removed=np.mean(ctrl),
                             fell_top=s_top < base[j], cleared_top=s_top <= det.threshold,
                             cleared_random=np.mean([c <= det.threshold for c in ctrl])))
    return pd.DataFrame(rows)
