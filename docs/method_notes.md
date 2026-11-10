# Method notes

## Pipeline
`ReplayLLM` → `TwoLayerMediatorElement` (Layer 1 → Layer 2) → AgentDojo `ToolsExecutor` → environment.
The mediator element wraps AgentDojo's executor: allowed calls are executed by it; refused calls receive a tool result
whose error reads `REFUSED BY SECURITY MEDIATOR: <decision> (<rule or Layer 2 alert>)`.

## Configurations
`none`, `layer1`, `layer2`, `both`. In `both`, Layer 2 scores only the calls that Layer 1 allows.

## Layer 1 rules (twolayer/rules/*.yaml)
Written only from the tool descriptions, each environment's initial data (payees, contacts, calendar participants,
Slack members) and the training user tasks. Slack rules use no Slack tasks at all. Actions: `block` (payment limit)
and `confirm` (everything else). Offline, `confirm` is simulated as a refusal.

| Environment | Rules |
|---|---|
| banking | BK-01 recipient must be a known payee or named in the request; BK-02 payment limit 2,200; BK-03 password change only if asked; BK-04 profile change only if asked; GEN-01 |
| workspace | WS-01 e-mail recipients; WS-02 file sharing; WS-03 calendar invitations; WS-04 delete/cancel only if asked; GEN-01 |
| travel | TR-01 e-mail recipients; TR-02 reservations only if asked; TR-03 calendar invitations; GEN-01 |
| slack | SL-01 direct messages to members; SL-02 invitations; SL-03 removing users; SL-04 posting to web pages; SL-05 no new links in messages; GEN-01 |

GEN-01: an action the user did not ask for, proposed after untrusted content was read, needs confirmation.

## Layer 2
Isolation Forest, 200 trees, `max_samples='auto'`, trained on the 143 benign calls of the 38 training runs.
Score = −`score_samples`. Threshold: the value exceeded by at most 5% of the 47 benign validation calls (0.6018 for
seed 0). Explanations: SHAP `TreeExplainer`, sign flipped so that positive contributions raise the anomaly score.

## Decision record (one JSON line per proposed call)
`run_id, call_idx, suite, tool, args, layer1 {decision, rule, reason}, layer2 {score, threshold, alert,
top_features [feature, value, contribution] x 3}, decision, decided_by, time_ms`.

## Estimates and their assumptions
* After a refusal the replayed agent stops and reports that it could not finish. A real agent might try again or
  carry on, so attack success and utility under a defence are estimates.
* Calls that are allowed are replayed exactly as recorded; tool results come from the real AgentDojo environment.
* Replay fidelity without a defence: 723/726 runs give the recorded utility and security (99.6%).
* Utility can rise under a defence when the refused call was itself what made the task fail (for example banking
  user_task_10, "pay the bill like last month", where AgentDojo counts not paying as correct).

## Limitations
One model and one attack; AgentDojo v1's 27 injection tasks; one recorded run per task (seed variation only for
Layer 2); 143 benign training calls; features that are constant in benign training data (e.g. `unrequested_action`)
cannot be used by an Isolation Forest; no adaptive or mimicry attacks were tested.
