from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional


class CerberusError(Exception):
    """Base exception for Cerberus SDK errors."""
    pass


class ErrDenied(CerberusError):
    """Exception raised when Cerberus denies tool execution."""

    def __init__(self, rule_id: str, reason: str):
        self.rule_id = rule_id
        self.reason = reason
        super().__init__(f"cerberus: tool execution denied by rule {rule_id!r}: {reason}")


class Decision:
    """Represents an evaluation verdict from Cerberus."""

    def __init__(
        self,
        decision: str,
        rule_id: str = "",
        reason: str = "",
        masked_args: Optional[Dict[str, Any]] = None,
        epoch: Optional[int] = None,
        cached: bool = False,
    ):
        self.decision = decision
        self.rule_id = rule_id
        self.reason = reason
        self.masked_args = masked_args
        self.epoch = epoch
        self.cached = cached

    def allowed(self) -> bool:
        """Returns True if the decision is 'allow'."""
        return self.decision == "allow"

    @property
    def is_allowed(self) -> bool:
        return self.allowed()

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def __contains__(self, item: str) -> bool:
        return hasattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "decision": self.decision,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "cached": self.cached,
        }
        if self.masked_args is not None:
            d["masked_args"] = self.masked_args
        if self.epoch is not None:
            d["epoch"] = self.epoch
        return d

    def __repr__(self) -> str:
        return (
            f"Decision(decision={self.decision!r}, rule_id={self.rule_id!r}, "
            f"reason={self.reason!r}, cached={self.cached!r})"
        )


class MetricsSnapshot:
    def __init__(
        self,
        total_calls: int = 0,
        allowed_calls: int = 0,
        denied_calls: int = 0,
        cache_hits: int = 0,
        cache_misses: int = 0,
        retries: int = 0,
        errors: int = 0,
    ):
        self.total_calls = total_calls
        self.allowed_calls = allowed_calls
        self.denied_calls = denied_calls
        self.cache_hits = cache_hits
        self.cache_misses = cache_misses
        self.retries = retries
        self.errors = errors

    def __repr__(self) -> str:
        return (
            f"MetricsSnapshot(total={self.total_calls}, allowed={self.allowed_calls}, "
            f"denied={self.denied_calls}, hits={self.cache_hits}, "
            f"misses={self.cache_misses}, retries={self.retries}, errors={self.errors})"
        )


class _CachedVerdict:
    def __init__(self, decision: Decision, expires_at: float):
        self.decision = decision
        self.expires_at = expires_at


class CerberusClient:
    """Client for evaluating tool calls against Cerberus policy engine."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8089",
        key_id: str = "",
        max_retries: int = 1,
        retry_delay: float = 0.05,
        cache_ttl: float = 60.0,
        disable_cache: bool = False,
        timeout: float = 5.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.key_id = key_id
        self.max_retries = max_retries if max_retries >= 0 else 1
        self.retry_delay = retry_delay if retry_delay > 0 else 0.05
        self.cache_ttl = cache_ttl if cache_ttl > 0 else 60.0
        self.disable_cache = disable_cache
        self.timeout = timeout

        self._lock = threading.Lock()
        self._cache: Dict[str, _CachedVerdict] = {}

        self._total_calls = 0
        self._allowed_calls = 0
        self._denied_calls = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._retries = 0
        self._errors = 0

    def metrics(self) -> MetricsSnapshot:
        with self._lock:
            return MetricsSnapshot(
                total_calls=self._total_calls,
                allowed_calls=self._allowed_calls,
                denied_calls=self._denied_calls,
                cache_hits=self._cache_hits,
                cache_misses=self._cache_misses,
                retries=self._retries,
                errors=self._errors,
            )

    def _normalize_args(self, args: Any) -> Dict[str, Any]:
        if args is None:
            return {}
        if isinstance(args, dict):
            return args
        try:
            return json.loads(json.dumps(args))
        except Exception as e:
            raise CerberusError(f"cerberus: normalize args: {e}") from e

    def _hash_tool_call(self, tool: str, args: Dict[str, Any]) -> str:
        canonical_args = json.dumps(args, sort_keys=True).encode("utf-8")
        h = hashlib.sha256()
        h.update(tool.encode("utf-8"))
        h.update(b"\x00")
        h.update(canonical_args)
        return h.hexdigest()

    def decide_tool(self, tool: str, args: Any = None) -> Decision:
        with self._lock:
            self._total_calls += 1

        args_map = self._normalize_args(args)
        cache_key = self._hash_tool_call(tool, args_map)

        now = time.time()
        if not self.disable_cache:
            with self._lock:
                entry = self._cache.get(cache_key)
                if entry is not None:
                    if now < entry.expires_at:
                        self._cache_hits += 1
                        d = Decision(
                            decision=entry.decision.decision,
                            rule_id=entry.decision.rule_id,
                            reason=entry.decision.reason,
                            masked_args=entry.decision.masked_args,
                            epoch=entry.decision.epoch,
                            cached=True,
                        )
                        if d.allowed():
                            self._allowed_calls += 1
                        else:
                            self._denied_calls += 1
                        return d
                    else:
                        del self._cache[cache_key]

        with self._lock:
            self._cache_misses += 1

        req_body = {
            "stage": "tool",
            "key_id": self.key_id,
            "tool_call": tool,
            "args": args_map,
        }
        body_bytes = json.dumps(req_body).encode("utf-8")

        try:
            dec = self._do_with_retry(body_bytes)
        except Exception as e:
            with self._lock:
                self._errors += 1
            raise

        with self._lock:
            if dec.allowed():
                self._allowed_calls += 1
            else:
                self._denied_calls += 1

            if not self.disable_cache and not dec.rule_id.startswith("internal."):
                self._cache[cache_key] = _CachedVerdict(
                    decision=dec,
                    expires_at=time.time() + self.cache_ttl,
                )

        return dec

    def _do_with_retry(self, body_bytes: bytes) -> Decision:
        url = f"{self.base_url}/v1/decide"
        headers = {
            "Content-Type": "application/json",
        }
        if self.key_id:
            headers["X-Cerberus-Key"] = self.key_id

        delay = self.retry_delay
        last_err: Optional[Exception] = None
        total_attempts = 1 + self.max_retries

        for attempt in range(total_attempts):
            if attempt > 0:
                with self._lock:
                    self._retries += 1
                time.sleep(delay)
                delay *= 2

            req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_status = resp.status
                    resp_bytes = resp.read()
            except urllib.error.HTTPError as e:
                # 5xx should be retried
                if e.code >= 500:
                    last_err = CerberusError(f"server error status {e.code}: {e.reason}")
                    continue
                # 4xx or others: return or raise
                err_body = e.read().decode("utf-8", errors="replace")
                raise CerberusError(f"unexpected status {e.code}: {err_body}") from e
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_err = e
                continue
            except Exception as e:
                last_err = e
                continue

            if resp_status != 200:
                raise CerberusError(f"unexpected status {resp_status}: {resp_bytes.decode('utf-8', errors='replace')}")

            try:
                data = json.loads(resp_bytes.decode("utf-8"))
            except Exception as e:
                raise CerberusError(f"unmarshal decision: {e}") from e

            return Decision(
                decision=data.get("decision", "deny"),
                rule_id=data.get("rule_id", ""),
                reason=data.get("reason", ""),
                masked_args=data.get("masked_args"),
                epoch=data.get("epoch"),
                cached=False,
            )

        raise CerberusError(f"cerberus: request failed after {total_attempts} attempts: {last_err}")
