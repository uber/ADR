"""Tests for guardrail base types."""

from guardrail.base_detector import BaseDetector, DetectionResult


class TestDetectionResult:
    def test_to_dict_includes_cost_fields(self):
        result = DetectionResult(
            task_id="task_001",
            is_malicious=True,
            confidence_score=0.9,
            total_messages=3,
            threat_messages=1,
            detections=[{"description": "test"}],
            method="unit-test",
            model_used="mock",
            analysis_time=1.5,
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.01,
        )
        data = result.to_dict()
        assert data["task_id"] == "task_001"
        assert data["is_malicious"] is True
        assert data["cost_usd"] == 0.01
        assert data["input_tokens"] == 100
        assert set(data) == {
            "task_id", "is_malicious", "confidence_score", "total_messages",
            "threat_messages", "detections", "method", "model_used",
            "analysis_time", "input_tokens", "output_tokens", "cost_usd",
        }


class _StubDetector(BaseDetector):
    def analyze_conversation(self, messages):
        return DetectionResult(
            task_id="conversation",
            is_malicious=False,
            confidence_score=0.1,
            total_messages=len(messages),
            threat_messages=0,
            detections=[],
            method="stub",
        )

    def is_available(self):
        return True


class TestBaseDetector:
    def test_analyze_task_sets_task_id(self):
        detector = _StubDetector("Stub")
        result = detector.analyze_task({"task_id": "task_042", "messages": [{"role": "user", "content": "hi"}]})
        assert result.task_id == "task_042"

    def test_analyze_task_returns_benign_on_error(self):
        class BrokenDetector(_StubDetector):
            def analyze_conversation(self, messages):
                raise RuntimeError("boom")

        detector = BrokenDetector("Broken")
        result = detector.analyze_task({"task_id": "task_099", "messages": []})
        assert result.is_malicious is False
        assert result.task_id == "task_099"
