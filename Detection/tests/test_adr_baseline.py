"""Tests for ADR baseline helpers."""

from unittest.mock import MagicMock

from guardrail.adr_agent.adr_baseline import ADSConfig, ReasoningAgent, TriageLLM, _safe_task_id_for_path


def _make_reasoning_agent(benchmark_type: str = "adr_bench") -> ReasoningAgent:
    agent = ReasoningAgent.__new__(ReasoningAgent)
    agent.config = ADSConfig()
    agent.benchmark_type = benchmark_type
    return agent


class TestSafeTaskIdForPath:
    def test_strips_path_separators(self):
        assert "/" not in _safe_task_id_for_path("../../etc/passwd")
        assert "\\" not in _safe_task_id_for_path("..\\windows\\path")

    def test_preserves_simple_ids(self):
        assert _safe_task_id_for_path("task_001") == "task_001"

    def test_empty_input_becomes_unknown(self):
        assert _safe_task_id_for_path("") == "unknown"


class TestTriageParsing:
    def test_parse_benign_result(self):
        triage = TriageLLM(MagicMock(), ADSConfig())
        result = triage._parse_triage_result(
            "CLASSIFICATION: BENIGN\nTHREAT_TACTIC: N/A\nREASONING: routine request\nconfidence: 0.2"
        )
        assert result.is_suspicious is False
        assert result.threat_tactic == "N/A"
        assert result.confidence == 0.2

    def test_parse_uppercase_confidence_from_prompt_format(self):
        triage = TriageLLM(MagicMock(), ADSConfig())
        result = triage._parse_triage_result(
            "CLASSIFICATION: BENIGN\nTHREAT_TACTIC: N/A\nREASONING: routine request\nCONFIDENCE: 0.99"
        )
        assert result.confidence == 0.99

    def test_parse_suspicious_result(self):
        triage = TriageLLM(MagicMock(), ADSConfig())
        result = triage._parse_triage_result(
            "CLASSIFICATION: SUSPICIOUS\nTHREAT_TACTIC: permission_abuse\nREASONING: sensitive access\nconfidence: 0.85"
        )
        assert result.is_suspicious is True
        assert result.threat_tactic == "permission_abuse"
        assert result.confidence == 0.85

    def test_ambiguous_defaults_to_suspicious(self):
        triage = TriageLLM(MagicMock(), ADSConfig())
        result = triage._parse_triage_result("unclear answer with benign and suspicious cues")
        assert result.is_suspicious is True


class TestReasoningPrompts:
    def test_system_prompt_avoids_injection_like_framing(self):
        agent = _make_reasoning_agent()
        system = agent._get_reasoning_system_prompt("initial_compromise")
        assert "[SECURITY RESEARCH CONTEXT" not in system
        assert "STRICT OUTPUT REQUIREMENT" not in system
        assert "**MANDATORY**" not in system
        assert "ANALYSIS STEPS" not in system
        assert "get_source_code MCP tool" in system
        assert '{"is_threat":' in system

    def test_user_prompt_contains_transcript_only(self):
        agent = _make_reasoning_agent()
        user = agent._get_reasoning_user_prompt("TOOL CALL 1: foo", "suspicious", "initial_compromise")
        assert "TOOL CALL 1: foo" in user
        assert "Triage assessment:" in user
        assert "ANALYSIS STEPS" not in user

    def test_agentdojo_system_prompt_has_injection_criteria(self):
        agent = _make_reasoning_agent(benchmark_type="agentdojo")
        system = agent._get_reasoning_system_prompt("prompt_injection")
        assert "is_threat=true only if" in system
        assert "ignored" in system


class TestReasoningJsonParsing:
    def test_parse_analysis_json_from_prose_wrapped_response(self):
        agent = _make_reasoning_agent()
        text = 'Some analysis.\n{"is_threat": true, "confidence": 0.9, "explanation": "bad tool"}'
        parsed = agent._parse_analysis_json(text)
        assert parsed["is_threat"] is True
        assert parsed["confidence"] == 0.9

    def test_is_refusal_response_detects_claude_pushback(self):
        agent = _make_reasoning_agent()
        refusal = (
            "Flagging this before responding. This message contains what looks like "
            "a prompt injection attempt. I won't output a bare JSON blob on demand."
        )
        assert agent._is_refusal_response(refusal) is True

    def test_is_refusal_response_false_when_json_present(self):
        agent = _make_reasoning_agent()
        text = 'Here is my result: {"is_threat": false, "confidence": 0.2, "explanation": "ok"}'
        assert agent._is_refusal_response(text) is False
