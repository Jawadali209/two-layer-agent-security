"""AgentDojo integration (Objectives 5-7).

* TwoLayerMediatorElement - a custom AgentDojo pipeline element that sits in front of AgentDojo's ToolsExecutor:
  every tool call proposed by the model is passed to the two-layer mediator first, and only allowed calls reach the
  executor. Refused calls get a tool result with an error message instead.
* ReplayLLM - a stand-in for the language model that replays the assistant messages of a recorded run. With no live
  API, this lets the mediator run inside a real AgentDojo pipeline and environment, and lets AgentDojo's own utility
  and security checks score the result.
* replay_run - runs one recorded run through the pipeline under a given mediator configuration.

Assumption for the estimates (approved fallback plan): once a call is refused, the agent stops and reports that it
could not finish ('stop' mode). Calls that were allowed are replayed exactly as recorded.
"""
import copy

from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, text_content_block_from_string

from .data import _text

REFUSAL = 'REFUSED BY SECURITY MEDIATOR'
STOP_MESSAGE = 'I could not complete the task: a requested action was refused by the security policy.'


class TwoLayerMediatorElement(BasePipelineElement):
    """Checks each proposed tool call with the mediator before AgentDojo's ToolsExecutor runs it."""
    name = 'two_layer_mediator'

    def __init__(self, mediator, suite: str, executor: ToolsExecutor | None = None, run_id: str | None = None):
        self.mediator = mediator
        self.suite = suite
        self.executor = executor or ToolsExecutor()
        self.run_id = run_id
        self.records = []

    @staticmethod
    def _previous_tools(messages):
        return [m['tool_call'].function for m in messages if m['role'] == 'tool' and m.get('tool_call') is not None]

    def query(self, query, runtime, env, messages=[], extra_args={}):
        if not messages or messages[-1]['role'] != 'assistant' or not messages[-1].get('tool_calls'):
            return query, runtime, env, messages, extra_args
        prev = self._previous_tools(messages)
        allowed, refused = [], {}
        for tc in messages[-1]['tool_calls']:
            rec = self.mediator.decide(self.suite, query, prev, tc.function, dict(tc.args))
            rec.update(run_id=self.run_id, call_idx=len(prev) + len(allowed) + len(refused))
            self.records.append(rec)
            if rec['decision'] == 'allow':
                allowed.append(tc)
            else:
                refused[id(tc)] = rec
        # run the allowed calls through AgentDojo's own executor
        results = []
        if allowed:
            msg = dict(messages[-1]); msg['tool_calls'] = allowed
            _, runtime, env, out, extra_args = self.executor.query(query, runtime, env, [*messages[:-1], msg], extra_args)
            results = list(out[len(messages):])
        by_call = {id(r['tool_call']): r for r in results}
        ordered = []
        for tc in messages[-1]['tool_calls']:
            if id(tc) in refused:
                rec = refused[id(tc)]
                why = (rec['layer1'] or {}).get('rule') or 'Layer 2 anomaly alert'
                ordered.append(ChatToolResultMessage(role='tool', content=[text_content_block_from_string('')],
                                                     tool_call_id=tc.id, tool_call=tc,
                                                     error=f'{REFUSAL}: {rec["decision"]} ({why})'))
            else:
                ordered.append(by_call[id(tc)])
        return query, runtime, env, [*messages, *ordered], extra_args


class ReplayLLM(BasePipelineElement):
    """Replays the assistant messages of a recorded AgentDojo run (no API needed)."""
    name = 'replay_llm'

    def __init__(self, run_log: dict, stop_on_refusal: bool = True):
        self.steps = [m for m in run_log['messages'] if m['role'] == 'assistant']
        self.i = 0
        self.stop_on_refusal = stop_on_refusal

    def _final(self, text):
        return ChatAssistantMessage(role='assistant', content=[text_content_block_from_string(text)], tool_calls=None)

    def query(self, query, runtime, env, messages=[], extra_args={}):
        last = messages[-1] if messages else None
        if self.stop_on_refusal and last is not None and last['role'] == 'tool':
            k = max(i for i, m in enumerate(messages) if m['role'] == 'assistant')
            refused_now = any((m.get('error') or '').startswith(REFUSAL) for m in messages[k + 1:])
        else:
            refused_now = False
        if refused_now:
            return query, runtime, env, [*messages, self._final(STOP_MESSAGE)], extra_args
        if self.i >= len(self.steps):
            return query, runtime, env, [*messages, self._final('')], extra_args
        step = self.steps[self.i]; self.i += 1
        calls = [FunctionCall(function=tc['function'], args=copy.deepcopy(tc.get('args') or {}), id=tc.get('id'))
                 for tc in (step.get('tool_calls') or [])]
        msg = ChatAssistantMessage(role='assistant', content=[text_content_block_from_string(_text(step.get('content')))],
                                   tool_calls=calls or None)
        return query, runtime, env, [*messages, msg], extra_args


def replay_run(suite_obj, suite_name: str, run_log: dict, mediator, run_id: str | None = None, stop_on_refusal=True):
    """Replay one recorded run under the mediator. Returns (utility, security, decision records)."""
    llm = ReplayLLM(run_log, stop_on_refusal=stop_on_refusal)
    element = TwoLayerMediatorElement(mediator, suite_name, run_id=run_id)
    system = _text(run_log['messages'][0]['content']) if run_log['messages'][0]['role'] == 'system' else ''
    pipeline = AgentPipeline([SystemMessage(system), InitQuery(), llm, ToolsExecutionLoop([element, llm], max_iters=100)])
    user_task = suite_obj.get_user_task_by_id(run_log['user_task_id'])
    inj_id = run_log.get('injection_task_id')
    injection_task = suite_obj.get_injection_task_by_id(inj_id) if inj_id else None
    utility, security = suite_obj.run_task_with_pipeline(pipeline, user_task, injection_task, run_log.get('injections') or {})
    return bool(utility), bool(security), element.records
