"""
W3C Trace Context support for MCP Server.

Implements W3C Trace Context specification (https://www.w3.org/TR/trace-context/)
for distributed tracing across services.

This module provides:
- traceparent header parsing and generation
- Trace context propagation for backend requests
- Correlation ID generation
"""

from __future__ import annotations

import random
import uuid
from contextvars import ContextVar
from typing import Any, Dict, Optional, Tuple

# W3C Trace Context header names
TRACEPARENT_HEADER = "traceparent"
TRACESTATE_HEADER = "tracestate"
CORRELATION_ID_HEADER = "x-correlation-id"

# Trace Context version
TRACE_VERSION = "00"

# Context variable for current trace context
_trace_context: ContextVar[Dict[str, Any]] = ContextVar("trace_context", default={})


def generate_trace_id() -> str:
    """Generate a 32-character hex trace ID (128 bits)."""
    return f"{random.getrandbits(128):032x}"


def generate_span_id() -> str:
    """Generate a 16-character hex span ID (64 bits)."""
    return f"{random.getrandbits(64):016x}"


def generate_correlation_id() -> str:
    """Generate a correlation ID (UUID format)."""
    return str(uuid.uuid4())


def parse_traceparent(header: str) -> Optional[Tuple[str, str, str, str]]:
    """
    Parse a W3C traceparent header.
    
    Format: {version}-{trace-id}-{parent-id}-{trace-flags}
    Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
    
    Returns:
        Tuple of (version, trace_id, parent_id, trace_flags) or None if invalid
    """
    try:
        parts = header.strip().split("-")
        if len(parts) != 4:
            return None
        
        version, trace_id, parent_id, trace_flags = parts
        
        # Validate version (2 hex chars)
        if len(version) != 2:
            return None
        
        # Validate trace_id (32 hex chars, not all zeros)
        if len(trace_id) != 32 or trace_id == "0" * 32:
            return None
        
        # Validate parent_id (16 hex chars, not all zeros)
        if len(parent_id) != 16 or parent_id == "0" * 16:
            return None
        
        # Validate trace_flags (2 hex chars)
        if len(trace_flags) != 2:
            return None
        
        return version, trace_id, parent_id, trace_flags
    
    except Exception:
        return None


def create_traceparent(
    trace_id: str,
    span_id: str,
    sampled: bool = True,
) -> str:
    """
    Create a W3C traceparent header value.
    
    Args:
        trace_id: 32-character hex trace ID
        span_id: 16-character hex span ID
        sampled: Whether this trace should be sampled
    
    Returns:
        traceparent header value
    """
    trace_flags = "01" if sampled else "00"
    return f"{TRACE_VERSION}-{trace_id}-{span_id}-{trace_flags}"


def get_current_context() -> Dict[str, Any]:
    """Get the current trace context."""
    return _trace_context.get()


def set_current_context(ctx: Dict[str, Any]) -> None:
    """Set the current trace context."""
    _trace_context.set(ctx)


def create_context(
    traceparent: Optional[str] = None,
    tracestate: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new trace context, optionally from incoming headers.
    
    Args:
        traceparent: Incoming traceparent header value
        tracestate: Incoming tracestate header value
        correlation_id: Incoming correlation ID
    
    Returns:
        Trace context dictionary
    """
    if traceparent:
        parsed = parse_traceparent(traceparent)
        if parsed:
            version, trace_id, parent_span_id, trace_flags = parsed
            sampled = trace_flags[-1] == "1"
        else:
            # Invalid traceparent, generate new
            trace_id = generate_trace_id()
            parent_span_id = None
            sampled = True
    else:
        trace_id = generate_trace_id()
        parent_span_id = None
        sampled = True
    
    span_id = generate_span_id()
    
    return {
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "sampled": sampled,
        "tracestate": tracestate or "",
        "correlation_id": correlation_id or generate_correlation_id(),
    }


def get_propagation_headers(ctx: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Get headers for propagating trace context to downstream services.
    
    Args:
        ctx: Trace context to use (defaults to current context)
    
    Returns:
        Dictionary of headers to include in outgoing requests
    """
    ctx = ctx or get_current_context()
    
    if not ctx:
        # No context, generate new one
        ctx = create_context()
    
    # Create new span for outgoing request
    traceparent = create_traceparent(
        ctx.get("trace_id", generate_trace_id()),
        generate_span_id(),  # New span for outgoing request
        ctx.get("sampled", True),
    )
    
    headers = {
        TRACEPARENT_HEADER: traceparent,
        CORRELATION_ID_HEADER: ctx.get("correlation_id", generate_correlation_id()),
    }
    
    if ctx.get("tracestate"):
        headers[TRACESTATE_HEADER] = ctx["tracestate"]
    
    return headers


def with_trace_context(func):
    """
    Decorator to ensure a function has trace context.
    Creates new context if none exists.
    """
    async def wrapper(*args, **kwargs):
        ctx = get_current_context()
        if not ctx:
            ctx = create_context()
            set_current_context(ctx)
        return await func(*args, **kwargs)
    return wrapper

