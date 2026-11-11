from __future__ import annotations

import inspect
from typing import Any, Callable, Optional

from .client import CerberusClient, CerberusError, Decision, ErrDenied


class GuardedExecutor:
    """Wraps tool execution with Cerberus policy authorization."""

    def __init__(self, client: Optional[CerberusClient]):
        if client is None:
            raise CerberusError("cerberus: guard has None client")
        self.client = client

    def execute(self, tool: str, args: Any, fn: Callable[..., Any]) -> Any:
        """Checks Cerberus policy before executing the given function."""
        dec = self.client.decide_tool(tool, args)
        if not dec.allowed():
            raise ErrDenied(rule_id=dec.rule_id, reason=dec.reason)

        effective_args = dec.masked_args if dec.masked_args is not None else args

        # Call fn with effective_args; if fn takes (tool, args), pass both.
        try:
            sig = inspect.signature(fn)
            num_params = len(sig.parameters)
            if num_params == 2:
                return fn(tool, effective_args)
        except (ValueError, TypeError):
            pass

        return fn(effective_args)

    def wrap(self, next_fn: Callable[[str, Any], Any]) -> Callable[[str, Any], Any]:
        """Provides a middleware wrapper around any tool runner function (tool, args) -> result."""
        def guarded(tool: str, args: Any) -> Any:
            return self.execute(
                tool,
                args,
                lambda eff_args: next_fn(tool, eff_args),
            )
        return guarded
