"""
State Manager for tracking participant states during test execution.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class ParticipantStatus(str, Enum):
    """Participant status enum."""
    WHITELISTED = "WHITELISTED"
    SUBSCRIBED = "SUBSCRIBED"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    UNSUBSCRIBED = "UNSUBSCRIBED"


class StateManager:
    """
    Manages participant state tracking across test execution.
    
    Tracks:
    - Current status of each participant
    - Participant metadata (subscriber_id, domains, etc.)
    - Test execution state
    """
    
    def __init__(self):
        """Initialize state manager."""
        self.participants: Dict[str, Dict[str, Any]] = {}
        self.test_results: Dict[str, Any] = {}
        self.created_at = datetime.now()
    
    def register_participant(
        self,
        subscriber_id: str,
        status: str = "WHITELISTED",
        unique_key_id: Optional[str] = None,
        domains: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Register a participant in state tracking.
        
        Args:
            subscriber_id: Participant subscriber ID
            status: Initial status
            unique_key_id: Unique key ID for V3 auth
            domains: List of domains
            metadata: Additional metadata
        """
        self.participants[subscriber_id] = {
            "subscriber_id": subscriber_id,
            "status": status,
            "unique_key_id": unique_key_id,
            "domains": domains or [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
    
    def update_status(self, subscriber_id: str, new_status: str):
        """
        Update participant status.
        
        Args:
            subscriber_id: Participant ID
            new_status: New status
        """
        if subscriber_id in self.participants:
            self.participants[subscriber_id]["status"] = new_status
            self.participants[subscriber_id]["updated_at"] = datetime.now().isoformat()
    
    def get_status(self, subscriber_id: str) -> Optional[str]:
        """Get current status of a participant."""
        return self.participants.get(subscriber_id, {}).get("status")
    
    def get_participant(self, subscriber_id: str) -> Optional[Dict[str, Any]]:
        """Get complete participant data."""
        return self.participants.get(subscriber_id)
    
    def participant_exists(self, subscriber_id: str) -> bool:
        """Check if participant is registered."""
        return subscriber_id in self.participants
    
    def get_all_participants(self) -> Dict[str, Dict[str, Any]]:
        """Get all registered participants."""
        return self.participants.copy()
    
    def update_metadata(self, subscriber_id: str, key: str, value: Any):
        """Update participant metadata."""
        if subscriber_id in self.participants:
            self.participants[subscriber_id]["metadata"][key] = value
            self.participants[subscriber_id]["updated_at"] = datetime.now().isoformat()
    
    def record_test_result(self, test_id: str, result: Dict[str, Any]):
        """
        Record test execution result.
        
        Args:
            test_id: Test identifier
            result: Test result data
        """
        self.test_results[test_id] = {
            **result,
            "recorded_at": datetime.now().isoformat()
        }
    
    def get_test_result(self, test_id: str) -> Optional[Dict[str, Any]]:
        """Get test result by ID."""
        return self.test_results.get(test_id)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of state manager status.
        
        Returns:
            Summary dictionary
        """
        status_counts = {}
        for participant in self.participants.values():
            status = participant["status"]
            status_counts[status] = status_counts.get(status, 0) + 1
        
        passed_tests = sum(1 for r in self.test_results.values() if r.get("passed", False))
        failed_tests = sum(1 for r in self.test_results.values() if not r.get("passed", False))
        
        return {
            "total_participants": len(self.participants),
            "status_distribution": status_counts,
            "total_tests": len(self.test_results),
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "session_duration": (datetime.now() - self.created_at).total_seconds()
        }
    
    def clear(self):
        """Clear all state."""
        self.participants.clear()
        self.test_results.clear()
