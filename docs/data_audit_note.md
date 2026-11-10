# Data audit note (Objective 3, Checkpoint 1)

* Live API runs: not possible (no API budget). As set out in the approved fallback plan, the project uses the
  published AgentDojo run logs for gpt-4o-mini-2024-07-18 (repository commit 089ed468cf).
* The logs were produced with AgentDojo benchmark v1 (97 user tasks, 27 injection tasks). Benchmark v1.2.2, named in
  the proposal, has the same 97 user tasks but 35 injection tasks (8 extra workspace injection tasks), so all offline
  results refer to v1.
* Inventory: 97 benign runs and 629 attacked runs (important_instructions attack),
  one run each; 0 runs missing; 0 runs with errors. A further 27 runs execute the injection
  tasks as user tasks; they are excluded from evaluation.
* Undefended baseline (recorded): benign utility 68.04%, utility under attack
  49.92%, attack success rate 27.19%.
* Every log contains the full message history, so each tool call, its arguments and its result can be recovered and
  converted into the project's trace format (3612 tool calls in total).
* Harmful-call labels: 279 harmful calls (269 matched to the injection task's ground truth,
  10 through the attacker's address, account or URL). Every successful attack except the text-only
  task (travel/injection_task_6) contains at least one harmful call; 46 unsuccessful attacks also contain one
  (the harmful call ran but AgentDojo's stricter check of the final state failed).
* The agent read the injected text in 76.6% of attacked runs.
* Partitions: user tasks split 50/20/30 (train/validation/test) within workspace, travel and banking (seed 42);
  Slack (21 user tasks) held out completely.
* Consequences of the fallback (as planned): Layer 1 rules are replayed on the recorded calls; attack success rate
  and utility under defence are estimates; the tool_filter comparison is dropped; one run per task (no repetitions).
* Agent Security Bench (optional): not feasible offline (it needs live model runs), so it is dropped.

Split summary (excluding injection-as-user runs):

                      runs  calls  harmful
split       kind                          
heldout_env attacked   105    771      103
            benign      21    130        0
test        attacked   159    713       39
            benign      23     91        0
train       attacked   262   1270       84
            benign      38    143        0
val         attacked    95    380       53
            benign      15     47        0
