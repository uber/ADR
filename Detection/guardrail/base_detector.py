#!/usr/bin/env python3
"""
Base Detector Interface

Defines the common interface for all threat detection baselines in the ADR benchmark.
This ensures consistency and extensibility across different detection methods.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """
    Standardized result from a threat detection analysis.
    """
    # Task-level results
    task_id: str
    is_malicious: bool
    confidence_score: float
    total_messages: int
    threat_messages: int

    # Individual message detections
    detections: List[Dict[str, Any]]

    # Metadata
    method: str
    model_used: Optional[str] = None
    analysis_time: Optional[float] = None

    # Cost tracking (for paper Figure 1c)
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cost_usd: Optional[float] = None

    # Optional validated Tier-1 audit data; never used as trusted model input.
    structured_triage: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            'task_id': self.task_id,
            'is_malicious': self.is_malicious,
            'confidence_score': self.confidence_score,
            'total_messages': self.total_messages,
            'threat_messages': self.threat_messages,
            'detections': self.detections,
            'method': self.method,
            'model_used': self.model_used,
            'analysis_time': self.analysis_time,
            'input_tokens': self.input_tokens,
            'output_tokens': self.output_tokens,
            'cost_usd': self.cost_usd
        }
        if self.structured_triage is not None:
            result['structured_triage'] = self.structured_triage
        return result


class BaseDetector(ABC):
    """
    Abstract base class for all threat detection baselines.

    All detector implementations should inherit from this class and implement
    the required methods for consistent behavior across the benchmark.
    """

    def __init__(self, name: str, **kwargs):
        """
        Initialize the detector.

        Args:
            name: Human-readable name of the detector
            **kwargs: Detector-specific configuration parameters
        """
        self.name = name
        self.config = kwargs
        logger.info(f"Initializing {self.name} detector")

    @abstractmethod
    def analyze_conversation(self, messages: List[Dict[str, Any]]) -> DetectionResult:
        """
        Analyze a conversation for threats.

        Args:
            messages: List of message dictionaries with 'role' and 'content'

        Returns:
            DetectionResult with analysis results
        """
        pass

    def analyze_task(self, task_data: Dict[str, Any]) -> DetectionResult:
        """
        Analyze a complete task for threats.

        Args:
            task_data: Task data dictionary containing messages and metadata

        Returns:
            DetectionResult with analysis results
        """
        task_id = task_data.get('task_id', 'unknown')
        messages = task_data.get('messages', [])

        try:
            result = self.analyze_conversation(messages)
            result.task_id = task_id
            return result
        except Exception as e:
            logger.error(f"Error analyzing task {task_id}: {e}")
            # Return safe default result
            return DetectionResult(
                task_id=task_id,
                is_malicious=False,
                confidence_score=0.0,
                total_messages=len(messages),
                threat_messages=0,
                detections=[],
                method=self.name,
                model_used=None
            )

    def get_info(self) -> Dict[str, Any]:
        """
        Get detector information and configuration.

        Returns:
            Dictionary with detector metadata
        """
        return {
            'name': self.name,
            'config': self.config,
            'type': self.__class__.__name__
        }

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the detector is available and properly configured.

        Returns:
            True if detector can be used, False otherwise
        """
        pass
