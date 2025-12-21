"""
Tests for Circuit Breaker implementation.

These tests validate:
1. Circuit breaker state transitions (closed → open → half_open → closed)
2. Failure threshold triggering
3. Recovery timeout behavior
4. Half-open state testing
"""

from __future__ import annotations

import pytest
import time
from unittest.mock import patch


# Add mcp_server to path
import sys
from pathlib import Path

mcp_server_root = Path(__file__).parent.parent.resolve()
if str(mcp_server_root) not in sys.path:
    sys.path.insert(0, str(mcp_server_root))


class TestCircuitBreakerStates:
    """Test circuit breaker state management."""
    
    def test_initial_state_is_closed(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker()
        assert cb._get_state("test_service") == "closed"
    
    def test_can_execute_when_closed(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker()
        assert cb.can_execute("test_service") is True
    
    def test_circuit_opens_after_failure_threshold(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=3)
        
        # Record 3 failures
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        assert cb._get_state("test_service") == "open"
        assert cb.can_execute("test_service") is False
    
    def test_success_resets_failure_count(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=3)
        
        # Record 2 failures (not enough to open)
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        # Success resets
        cb.record_success("test_service")
        
        # Record 2 more failures (still not enough)
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        assert cb._get_state("test_service") == "closed"
    
    def test_circuit_transitions_to_half_open_after_timeout(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        # Open the circuit
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        assert cb._get_state("test_service") == "open"
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        assert cb._get_state("test_service") == "half_open"
    
    def test_half_open_allows_limited_calls(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1, half_open_max_calls=2)
        
        # Open the circuit
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        # Should allow 2 calls in half-open
        assert cb.can_execute("test_service") is True
        cb.before_call("test_service")
        
        assert cb.can_execute("test_service") is True
        cb.before_call("test_service")
        
        # Third call should be blocked
        assert cb.can_execute("test_service") is False
    
    def test_success_in_half_open_closes_circuit(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        # Open the circuit
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        assert cb._get_state("test_service") == "half_open"
        
        # Success closes the circuit
        cb.record_success("test_service")
        
        assert cb._get_state("test_service") == "closed"
    
    def test_failure_in_half_open_reopens_circuit(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        # Open the circuit
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        assert cb._get_state("test_service") == "half_open"
        
        # Failure reopens the circuit
        cb.record_failure("test_service")
        
        assert cb._get_state("test_service") == "open"


class TestCircuitBreakerError:
    """Test circuit breaker error handling."""
    
    def test_before_call_raises_when_open(self):
        from mcp_server.server import CircuitBreaker, CircuitBreakerError
        
        cb = CircuitBreaker(failure_threshold=2)
        
        # Open the circuit
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        with pytest.raises(CircuitBreakerError) as exc_info:
            cb.before_call("test_service")
        
        assert exc_info.value.service == "test_service"
        assert exc_info.value.reset_after >= 0


class TestCircuitBreakerStatus:
    """Test circuit breaker status reporting."""
    
    def test_get_status_empty_initially(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker()
        status = cb.get_status()
        
        assert status == {}
    
    def test_get_status_shows_failures(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=5)
        
        cb.record_failure("service_a")
        cb.record_failure("service_a")
        cb.record_failure("service_b")
        
        status = cb.get_status()
        
        assert "service_a" in status
        assert status["service_a"]["failures"] == 2
        assert status["service_a"]["state"] == "closed"
        
        assert "service_b" in status
        assert status["service_b"]["failures"] == 1
    
    def test_get_status_shows_open_state(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=30.0)
        
        cb.record_failure("test_service")
        cb.record_failure("test_service")
        
        status = cb.get_status()
        
        assert status["test_service"]["state"] == "open"
        assert status["test_service"]["reset_in"] > 0
        assert status["test_service"]["reset_in"] <= 30.0


class TestCircuitBreakerIsolation:
    """Test that circuits are isolated per service."""
    
    def test_services_have_independent_circuits(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=2)
        
        # Open circuit for service_a
        cb.record_failure("service_a")
        cb.record_failure("service_a")
        
        assert cb.can_execute("service_a") is False
        assert cb.can_execute("service_b") is True
    
    def test_success_only_affects_own_service(self):
        from mcp_server.server import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=3)
        
        # Record failures for both
        cb.record_failure("service_a")
        cb.record_failure("service_a")
        cb.record_failure("service_b")
        
        # Success for service_a
        cb.record_success("service_a")
        
        # service_a should be reset, service_b unchanged
        assert cb._failures.get("service_a", 0) == 0
        assert cb._failures.get("service_b", 0) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

