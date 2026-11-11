#!/usr/bin/env python3
"""Unit tests for Cerberus Python SDK."""

import io
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure sdk/python is on sys.path
sdk_dir = Path(__file__).resolve().parent
if str(sdk_dir) not in sys.path:
    sys.path.insert(0, str(sdk_dir))

from cerberus_sdk import CerberusClient, CerberusError, Decision, ErrDenied, GuardedExecutor


class FakeClient:
    """Mock CerberusClient for testing GuardedExecutor without network."""

    def __init__(self, verdict: str = "allow", rule_id: str = "test.allow", reason: str = "ok", masked_args=None):
        self.verdict = verdict
        self.rule_id = rule_id
        self.reason = reason
        self.masked_args = masked_args
        self.calls = []

    def decide_tool(self, tool: str, args=None) -> Decision:
        self.calls.append((tool, args))
        return Decision(
            decision=self.verdict,
            rule_id=self.rule_id,
            reason=self.reason,
            masked_args=self.masked_args,
            cached=False,
        )


class TestDecision(unittest.TestCase):
    def test_decision_properties_and_dict_access(self):
        d = Decision(
            decision="allow",
            rule_id="tool.allowed",
            reason="policy passed",
            masked_args={"key": "safe"},
            epoch=123,
            cached=True,
        )
        assert d.allowed() is True
        assert d.is_allowed is True
        assert d["decision"] == "allow"
        assert d["rule_id"] == "tool.allowed"
        assert d.get("reason") == "policy passed"
        assert d.get("missing", "default") == "default"
        assert "rule_id" in d
        assert d.to_dict()["epoch"] == 123
        assert d.to_dict()["masked_args"] == {"key": "safe"}

    def test_decision_deny(self):
        d = Decision(decision="deny", rule_id="shield.cmd.dangerous", reason="rm -rf forbidden")
        assert d.allowed() is False
        assert d.is_allowed is False


class TestGuardedExecutor(unittest.TestCase):
    def test_guarded_executor_allow(self):
        client = FakeClient(verdict="allow")
        guard = GuardedExecutor(client)

        executed = False

        def my_tool(args):
            nonlocal executed
            executed = True
            return f"executed with {args['cmd']}"

        res = guard.execute("bash", {"cmd": "echo hi"}, my_tool)
        assert executed is True
        assert res == "executed with echo hi"
        assert len(client.calls) == 1

    def test_guarded_executor_masked_args(self):
        client = FakeClient(verdict="allow", masked_args={"cmd": "echo [REDACTED]"})
        guard = GuardedExecutor(client)

        def my_tool(args):
            return args["cmd"]

        res = guard.execute("bash", {"cmd": "echo secret123"}, my_tool)
        assert res == "echo [REDACTED]"

    def test_guarded_executor_deny_raises_err_denied(self):
        client = FakeClient(verdict="deny", rule_id="shield.rm", reason="blocked")
        guard = GuardedExecutor(client)

        executed = False

        def my_tool(args):
            nonlocal executed
            executed = True
            return "should not run"

        with self.assertRaises(ErrDenied) as cm:
            guard.execute("bash", {"cmd": "rm -rf /"}, my_tool)

        assert executed is False
        assert cm.exception.rule_id == "shield.rm"
        assert cm.exception.reason == "blocked"
        assert "tool execution denied by rule 'shield.rm': blocked" in str(cm.exception)

    def test_guarded_executor_wrap(self):
        client = FakeClient(verdict="allow")
        guard = GuardedExecutor(client)

        runner = lambda tool, args: f"Ran {tool}: {args.get('path')}"
        wrapped = guard.wrap(runner)

        res = wrapped("read_file", {"path": "/tmp/test"})
        assert res == "Ran read_file: /tmp/test"


class TestCerberusClientCachingAndRetry(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_client_decide_and_cache(self, mock_urlopen):
        # Prepare mock response
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "decision": "allow",
            "rule_id": "rule.test",
            "reason": "allowed",
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        client = CerberusClient(base_url="http://mock-server:8089", key_id="k-test", cache_ttl=0.2)

        # 1. First call -> network call
        d1 = client.decide_tool("ls", {"dir": "/var"})
        assert d1.allowed() is True
        assert d1.cached is False
        assert mock_urlopen.call_count == 1

        # 2. Second call with same args -> cache hit
        d2 = client.decide_tool("ls", {"dir": "/var"})
        assert d2.allowed() is True
        assert d2.cached is True
        assert mock_urlopen.call_count == 1

        # 3. Third call with different args -> cache miss, network call
        d3 = client.decide_tool("ls", {"dir": "/tmp"})
        assert d3.allowed() is True
        assert d3.cached is False
        assert mock_urlopen.call_count == 2

        # 4. Wait for TTL to expire
        time.sleep(0.25)
        d4 = client.decide_tool("ls", {"dir": "/var"})
        assert d4.allowed() is True
        assert d4.cached is False
        assert mock_urlopen.call_count == 3

        m = client.metrics()
        assert m.total_calls == 4
        assert m.cache_hits == 1
        assert m.cache_misses == 3
        assert m.allowed_calls == 4

    @patch("urllib.request.urlopen")
    def test_client_retry_on_503(self, mock_urlopen):
        import urllib.error

        # First attempt fails with 503 HTTPError, second succeeds
        error_resp = urllib.error.HTTPError(
            url="http://mock-server:8089/v1/decide",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=io.BytesIO(b"server busy"),
        )
        ok_resp = MagicMock()
        ok_resp.status = 200
        ok_resp.read.return_value = json.dumps({
            "decision": "allow",
            "rule_id": "rule.retry",
            "reason": "recovered",
        }).encode("utf-8")
        ok_resp.__enter__.return_value = ok_resp

        mock_urlopen.side_effect = [error_resp, ok_resp]

        client = CerberusClient(base_url="http://mock-server:8089", max_retries=1, retry_delay=0.01)
        dec = client.decide_tool("ping", {})

        assert dec.allowed() is True
        assert mock_urlopen.call_count == 2
        m = client.metrics()
        assert m.retries == 1
        assert m.allowed_calls == 1


if __name__ == "__main__":
    unittest.main()
