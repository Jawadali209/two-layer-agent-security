# Two-Layer Agentic AI Security via Tool-Call Mediation and Behavioural Anomaly Detection

MSc Cyber Security project, University of the West of Scotland (2026–27). Author: Sanil Giri.

This repository contains the code, rule files, trace dataset, notebooks and results of a two-layer runtime defence
for LLM agents against indirect prompt injection, evaluated on the [AgentDojo](https://github.com/ethz-spylab/agentdojo)
benchmark (Debenedetti et al., 2024).

* **Layer 1 – tool-call mediator.** Deterministic rules (one YAML file per environment) check every tool call the
  agent proposes before it runs: permitted recipients and accounts, payment limits, and a confirmation step for
  actions the user did not ask for after untrusted content has been read.
* **Layer 2 – behavioural anomaly detector.** An Isolation Forest (Liu, Ting and Zhou, 2008) trained only on benign
  tool calls scores each proposed call; calls above a threshold set at a 5% false-alarm rate go to the confirmation
  step. Every alert carries its three most important SHAP features (Lundberg and Lee, 2017).
* **Baseline.** An n-gram detector over tool-call sequences in the style of Forrest et al. (1996).

## How the evaluation was run (offline)

No API budget was available, so the project followed the fallback plan in its approved specification:

* **Data:** the run logs that AgentDojo publishes for `gpt-4o-mini-2024-07-18` (repository commit `089ed468cf`):
  97 benign runs and 629 runs under the `important_instructions` attack. These logs use **AgentDojo benchmark v1**
  (97 user tasks, 27 injection tasks), so all results refer to v1.
* **Replay:** a `ReplayLLM` pipeline element replays each recorded run inside a real AgentDojo environment, with the
  two-layer mediator placed in front of AgentDojo's `ToolsExecutor`. AgentDojo's own checks then score utility and
  security. With the mediator switched off, the replay reproduces the recorded result in 723 of 726 runs (99.6%).
* **Assumption:** when the mediator refuses a call (a block, or a confirmation, which is simulated as a refusal
  because no human is present) the agent stops. Attack success rate and utility under a defence are therefore
  **estimates**. AgentDojo's `tool_filter` comparison is dropped, because the logs contain it only for gpt-4o.
* **Partitions:** user tasks are split 50/20/30 into train/validation/test inside workspace, travel and banking
  (seed 42). The Slack environment is held out completely to test generalisation.

## Main results (test user tasks; Layer 2 averaged over 5 training seeds)

| Configuration | Attack success rate | Benign utility | Utility under attack |
|---|---|---|---|
| No defence | 18.9% | 69.6% | 47.2% |
| Layer 1 only | 0.6% | 60.9% | 44.0% |
| Layer 2 only | 16.7% (± 2.1) | 73.9% | 52.8% |
| Both layers | 0.6% | 65.2% | 49.7% |

| Call-level detection (test) | Recall | False-alarm rate (benign runs) | ROC-AUC |
|---|---|---|---|
| Layer 1 only | 100% (39/39) | 5.5% | – |
| Layer 2 only | 43.6% | 3.3% | 0.927 (95% CI 0.890–0.956) |
| n-gram baseline | 7.7% | 0.0% | 0.822 |

* **Held-out environment (Slack):** Layer 2 ROC-AUC falls to 0.734 with a 20% false-alarm rate. Layer 1 cuts the
  attack success rate from 57.1% to 9.5%, but benign utility falls from 66.7% to 47.6%.
* **Explanations:** the global SHAP feature ranking is stable across 10 retraining seeds (mean Spearman 0.987), but the
  top-1 feature of an individual alert agrees with seed 0 in only 63.8% of cases. Replacing the top-3 SHAP features
  with their benign median clears 100% of alerts, against 8.2% for three random features.
* **Added time per call (Colab):** Layer 1 0.05 ms, Layer 2 16.9 ms (median), SHAP explanation 4.6 ms per alert.

All numbers come from `results/stage3/`. The notebooks in `notebooks/` are the executed Google Colab runs.

## Repository layout

```
twolayer/                 Python package
  catalog.py              environment-neutral tool categories
  data.py                 log loading, trace dataset, injection-task classification, harmful-call labels
  splits.py               task-disjoint partitions (Slack held out)
  features.py             47 environment-neutral features per proposed call
  layer1.py, rules/*.yaml Layer 1 rule engine and the rule file for each environment
  layer2.py               Isolation Forest, 5% false-alarm threshold, SHAP explanations
  ngram.py                n-gram baseline
  mediator.py             two-layer mediator and decision records
  agentdojo_bridge.py     AgentDojo pipeline element, ReplayLLM and replay_run
  evaluate.py             metrics, ablation, seed stability, removal test
notebooks/                Stage 1 (Objectives 2-4), Stage 2 (5-6), Stage 3 (7-9) – executed in Colab
data/                     the labelled per-call trace dataset (see data/README.md)
results/stage1..3/        every table, figure and decision-record file produced by the notebooks
docs/                     data audit note, label check, method notes
examples/                 how to put the mediator in front of a live model (not run in this project)
```

## Reproducing the results

**Google Colab (as used in the project):** upload `notebooks/Stage1_Data_Audit_and_Traces.ipynb`, choose
*Runtime → Run all*, then do the same for Stage 2 and Stage 3. The notebooks create the folder
`MyDrive/TwoLayerAgentSecurity/`, download the published AgentDojo logs, install the pinned packages and write the
results there. Stage 3 takes about 15–20 minutes.

**Locally:** Python 3.10+ (the project used 3.13), then

```bash
pip install -r requirements.txt
jupyter nbconvert --to notebook --execute notebooks/Stage1_Data_Audit_and_Traces.ipynb
jupyter nbconvert --to notebook --execute notebooks/Stage2_Layers_and_Integration.ipynb
jupyter nbconvert --to notebook --execute notebooks/Stage3_Evaluation.ipynb
```

Outside Colab the notebooks work in `./TwoLayerAgentSecurity/`. With the pinned versions the outputs are identical
to the files in `results/` (checked file by file; differences are at most 1e-15 from floating-point rounding).

## Using the mediator with a live model

`examples/live_agentdojo_example.py` shows how `TwoLayerMediatorElement` is placed in a normal AgentDojo pipeline
with an OpenAI model. It needs an `OPENAI_API_KEY` and was **not** run in this project.

## Limitations

One model, one attack and AgentDojo's fixed injection tasks; one recorded run per task; estimates that assume the
agent stops after a refusal; a small benign training set (143 calls); and no protection against mimicry attacks that
imitate normal behaviour. See `docs/method_notes.md`.

## References

* Debenedetti, E. et al. (2024) 'AgentDojo: a dynamic environment to evaluate prompt injection attacks and defenses
  for LLM agents', *NeurIPS 37*, pp. 82895–82920.
* Forrest, S. et al. (1996) 'A sense of self for Unix processes', *IEEE Symposium on Security and Privacy*, pp. 120–128.
* Liu, F.T., Ting, K.M. and Zhou, Z.-H. (2008) 'Isolation forest', *ICDM 2008*, pp. 413–422.
* Lundberg, S.M. and Lee, S.-I. (2017) 'A unified approach to interpreting model predictions', *NeurIPS 30*, pp. 4765–4774.

## Licence

Code: MIT (see `LICENSE`). The trace dataset in `data/` is derived from AgentDojo's published run logs, which are
MIT-licensed; see `THIRD_PARTY_NOTICES.md`. All data is synthetic; no real accounts or people are involved.
