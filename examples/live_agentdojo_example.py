"""Putting the two-layer mediator in front of a live model in AgentDojo.

NOT RUN in this project (no API budget). It shows how the same pipeline element used in the offline replay is placed
in a normal AgentDojo pipeline. Run from the repository root with OPENAI_API_KEY set:

    python examples/live_agentdojo_example.py
"""
import os
import sys

import openai
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suite

from twolayer.agentdojo_bridge import TwoLayerMediatorElement
from twolayer.evaluate import train_detector
from twolayer.mediator import TwoLayerMediator

SUITE, USER_TASK, INJECTION_TASK = 'banking', 'user_task_0', 'injection_task_0'
MODEL = 'gpt-4o-mini-2024-07-18'

# Layer 2: retrain the seed-0 detector from the released dataset (benign training calls, validation threshold)
calls = pd.read_csv('data/calls.csv')
X = pd.read_csv('data/features.csv', index_col='call_row')
ev = calls.loc[X.index]
detector = train_detector(X, (ev.split == 'train') & (ev.kind == 'benign'), (ev.split == 'val') & (ev.kind == 'benign'))

suite = get_suite('v1', SUITE)
llm = OpenAILLM(openai.OpenAI(api_key=os.environ['OPENAI_API_KEY']), MODEL)
mediator_element = TwoLayerMediatorElement(TwoLayerMediator(detector=detector, config='both'), SUITE)
pipeline = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                          ToolsExecutionLoop([mediator_element, llm])])
pipeline.name = MODEL                      # the attack uses the model name in its injected text

user_task = suite.get_user_task_by_id(USER_TASK)
injection_task = suite.get_injection_task_by_id(INJECTION_TASK)
injections = load_attack('important_instructions', suite, pipeline).attack(user_task, injection_task)
utility, attack_succeeded = suite.run_task_with_pipeline(pipeline, user_task, injection_task, injections)
print(f'utility={utility} attack_succeeded={attack_succeeded}')
for rec in mediator_element.records:
    print(rec['tool'], '->', rec['decision'], rec['decided_by'] or '')
