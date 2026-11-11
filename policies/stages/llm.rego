package stages.llm

# AI LLM stage adapter — dispatches to the shared AI stage implementation.

import rego.v1

decision := data.stages.ai.decision
