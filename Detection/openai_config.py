#!/usr/bin/env python3
"""
OpenAI Configuration Module for ADR Platform

This module provides a standardized OpenAI client configuration.
All OpenAI clients in the ads_platform should use this configuration.

Also provides Claude client configuration for API access.
"""

import os
import warnings
import openai
from openai import OpenAI
from typing import Dict, Any, Optional


def calculate_cost(cost_per_1m_input: float, cost_per_1m_output: float,
                   input_tokens: int, output_tokens: int) -> float:
    """Return cost in USD given per-1M-token rates and token counts.

    Rates come from config_detector.yaml (cost_per_1m_input / cost_per_1m_output)
    so that pricing stays co-located with the model definition.
    """
    return (input_tokens * cost_per_1m_input + output_tokens * cost_per_1m_output) / 1_000_000


def get_openai_client() -> OpenAI:
    """
    Get a configured OpenAI client using OPENAI_API_KEY environment variable.
    All ads_platform components should use this function to get their OpenAI client.

    Set the OPENAI_BASE_URL environment variable to point the client at any
    OpenAI-compatible API endpoint (passed to the SDK as base_url).

    Returns:
        OpenAI: Configured client
    """
    base_url = os.environ.get("OPENAI_BASE_URL")
    if base_url:
        return OpenAI(api_key=os.environ["OPENAI_API_KEY"], base_url=base_url)
    return OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def get_openai_config() -> Dict[str, Any]:
    """
    Get the OpenAI configuration dictionary.

    Returns:
        Dict containing api_key, and base_url when OPENAI_BASE_URL is set
    """
    config = {
        'api_key': os.environ["OPENAI_API_KEY"],
    }
    base_url = os.environ.get("OPENAI_BASE_URL")
    if base_url:
        config['base_url'] = base_url
    return config


def create_chat_completion(
    model: str = 'gpt-4o',
    messages: Optional[list] = None,
    **kwargs
) -> Any:
    """
    Create a chat completion using the configured client.

    Args:
        model: Model to use (defaults to gpt-4o)
        messages: Messages for the completion
        **kwargs: Additional arguments for the completion

    Returns:
        Chat completion response
    """
    if messages is None:
        raise ValueError("messages is required")

    client = get_openai_client()
    return client.chat.completions.create(
        model=model,
        messages=messages,
        **kwargs
    )


def create_reasoning_completion(
    model: str = 'claude-sonnet-4-6',
    messages: Optional[list] = None,
    max_tokens: int = 4000,
    **kwargs
) -> Dict[str, Any]:
    """
    Create a reasoning completion using the Anthropic API via Claude CLI.

    Args:
        model: Reasoning model to use
        messages: Messages for the completion
        max_tokens: Maximum tokens to generate
        **kwargs: Additional arguments for the completion

    Returns:
        Reasoning completion response
    """
    if messages is None:
        raise ValueError("messages is required")

    client = get_openai_client()
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            **kwargs
        )

        # Guard against empty responses
        if not response.choices or not response.choices[0].message:
            raise RuntimeError(f"Empty response from model {model}")
        content = response.choices[0].message.content or ""

        # Convert OpenAI-style response to dict format
        return {
            'content': [{'text': content, 'type': 'text'}],
            'model': response.model,
            'usage': {
                'input_tokens': response.usage.prompt_tokens if response.usage else 0,
                'output_tokens': response.usage.completion_tokens if response.usage else 0
            }
        }
    except Exception as e:
        raise RuntimeError(f"Failed to call model: {str(e)}")


if __name__ == "__main__":
    # Test the configuration
    print("Testing OpenAI configuration...")

    try:
        client = get_openai_client()
        print(f"✅ Client created successfully")

        response = create_chat_completion(
            messages=[{'role': 'user', 'content': 'Hello, are you working?'}],
            max_tokens=10
        )
        print(f"✅ Test completion successful")
        print(f"   Response: {response.choices[0].message.content[:50]}...")

    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
