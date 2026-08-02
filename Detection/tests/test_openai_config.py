"""Tests for openai_config helpers."""

import pytest

from openai_config import calculate_cost, get_openai_client, get_openai_config


class TestCalculateCost:
    def test_zero_tokens(self):
        assert calculate_cost(2.50, 10.00, 0, 0) == 0.0

    def test_input_only(self):
        # 1M input tokens at $2.50/1M
        assert calculate_cost(2.50, 10.00, 1_000_000, 0) == pytest.approx(2.50)

    def test_output_only(self):
        assert calculate_cost(2.50, 10.00, 0, 1_000_000) == pytest.approx(10.00)

    def test_mixed_tokens(self):
        cost = calculate_cost(3.00, 15.00, 500_000, 200_000)
        expected = (500_000 * 3.00 + 200_000 * 15.00) / 1_000_000
        assert cost == pytest.approx(expected)


class TestGetOpenaiClient:
    def test_default_base_url(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        client = get_openai_client()
        assert str(client.base_url) == "https://api.openai.com/v1/"

    def test_custom_base_url(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://llm.example.com/v1")
        client = get_openai_client()
        assert str(client.base_url) == "https://llm.example.com/v1/"


class TestGetOpenaiConfig:
    def test_no_base_url_by_default(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        config = get_openai_config()
        assert config == {"api_key": "test-key"}

    def test_includes_base_url_when_set(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://llm.example.com/v1")
        config = get_openai_config()
        assert config["base_url"] == "https://llm.example.com/v1"
