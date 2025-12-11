from __future__ import annotations

import signal
import sys
from typing import Any

from starlette.responses import JSONResponse

from .server import mcp, _ALL_TOOLS, server_cfg

# Global reference to mcp for accessing session manager
_mcp_instance = mcp


def main() -> None:
    try:
        # Patch uvicorn.Config to wrap the app with discovery endpoint
        # FastMCP uses uvicorn.Config/Server internally
        import uvicorn
        
        original_config_init = uvicorn.Config.__init__
        
        def patched_config_init(self: Any, app: Any, *args: Any, **kwargs: Any) -> None:
            """Wrap uvicorn.Config.__init__ to inject discovery endpoint and fix host headers."""
            # Wrap the ASGI app before passing to Config
            original_asgi_app = app
            
            async def wrapped_asgi_app(scope: Any, receive: Any, send: Any) -> None:
                """ASGI app wrapper that intercepts /mcp/discovery and fixes host headers for ngrok."""
                if scope["type"] == "http":
                    path = scope.get("path", "")
                    query_string = scope.get("query_string", b"")
                    method = scope.get("method", "")
                    
                    # Enhanced logging for Agent Builder debugging
                    if path.startswith("/mcp"):
                        import logging
                        logger = logging.getLogger("mcp_server.wrapper")
                        query_str = query_string.decode("utf-8", errors="ignore") if query_string else ""
                        logger.info(f"[ASGI Request] {method} {path}?{query_str}")
                        
                        # Log key headers for debugging
                        headers_dict = {k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore") 
                                       for k, v in scope.get("headers", [])}
                        if "accept" in headers_dict:
                            logger.info(f"[ASGI] Accept: {headers_dict['accept']}")
                        if "content-type" in headers_dict:
                            logger.info(f"[ASGI] Content-Type: {headers_dict['content-type']}")
                    
                    # Fix host header for ngrok - replace with localhost to prevent "421 Misdirected Request"
                    # This allows ngrok forwarding to work correctly
                    headers = list(scope.get("headers", []))
                    accept_header = None
                    
                    for i, (name, value) in enumerate(headers):
                        if name == b"host":
                            # Replace ngrok host with localhost to pass Starlette's host validation
                            # Store original host in a custom header for reference
                            headers[i] = (b"host", b"localhost:9000")
                            headers.append((b"x-original-host", value))
                        elif name == b"accept":
                            accept_header = value.decode("utf-8", errors="ignore")
                    
                    # If no host header found, add one
                    if not any(name == b"host" for name, _ in headers):
                        headers.append((b"host", b"localhost:9000"))
                    
                    # Update scope with modified headers and query_string
                    scope = dict(scope)
                    scope["headers"] = headers
                    scope["query_string"] = query_string
                    
                    # Ensure Accept header is set for MCP requests
                    # FastMCP streamable-http expects text/event-stream or application/json
                    if path.startswith("/mcp") and method == "GET":
                        has_accept = any(name == b"accept" for name, _ in headers)
                        if not has_accept:
                            headers.append((b"accept", b"text/event-stream, application/json"))
                            scope["headers"] = headers
                    
                    # Handle /mcp/messages endpoint for Agent Builder
                    # Agent Builder sends: POST /mcp/messages/?session_id=XXX
                    # FastMCP streamable-http expects: POST /mcp?session_id=XXX
                    if path.startswith("/mcp/messages"):
                        import logging
                        logger = logging.getLogger("mcp_server.wrapper")
                        logger.info(f"[ASGI Redirect] {method} {path} -> POST /mcp?{query_string.decode('utf-8', errors='ignore')}")
                        
                        # Redirect POST /mcp/messages to POST /mcp with same query string
                        # Create new scope with modified path
                        new_scope = dict(scope)
                        new_scope["path"] = "/mcp"
                        new_scope["query_string"] = query_string  # Preserve session_id
                        
                        # Ensure Content-Type is set for POST requests
                        has_content_type = any(name == b"content-type" for name, _ in new_scope["headers"])
                        if not has_content_type and method == "POST":
                            new_scope["headers"] = list(new_scope["headers"])
                            new_scope["headers"].append((b"content-type", b"application/json"))
                        
                        await original_asgi_app(new_scope, receive, send)
                        return
                    
                    if path == "/mcp/discovery" and method == "GET":
                        response = JSONResponse({
                            "version": "1.0",
                            "server": server_cfg.get("name", "simple-gpt-mcp"),
                            "transport": "streamable-http",
                            "endpoint": "/mcp",
                            "tools": sorted([{"name": name} for name in _ALL_TOOLS], key=lambda x: x["name"]),
                            "tool_count": len(_ALL_TOOLS),
                            "note": "For detailed tool information, use the MCP protocol endpoint /mcp or call observability.discovery tool",
                        })
                        await response(scope, receive, send)
                        return
                    
                # Forward all other requests to original app with fixed host header
                # Intercept responses to log session_id if present
                if scope["type"] == "http" and scope.get("path", "").startswith("/mcp"):
                    # Wrap send to intercept response headers and body
                    import logging
                    logger = logging.getLogger("mcp_server.wrapper")
                    response_body_chunks = []
                    extracted_session_id = None  # Store session_id extracted from body
                    
                    async def send_wrapper(message: Any) -> None:
                        if message.get("type") == "http.response.start":
                            status = message.get("status")
                            headers_list = list(message.get("headers", []))
                            headers_dict = {k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore")
                                          for k, v in headers_list}
                            
                            # Log response status and all headers for /mcp requests
                            logger.info(f"[ASGI Response] Status: {status} for {method} {path}")
                            logger.info(f"[ASGI Response Headers] {list(headers_dict.keys())}")
                            
                            # Extract session_id from query string or generate one
                            session_id_to_set = None
                            
                            if query_string:
                                query_str = query_string.decode("utf-8", errors="ignore")
                                if "session_id=" in query_str:
                                    for param in query_str.split("&"):
                                        if param.startswith("session_id="):
                                            session_id_to_set = param.split("=", 1)[1]
                                            logger.info(f"[ASGI] Session ID from query: {session_id_to_set}")
                                            break
                            
                            # For GET /mcp without session_id (initial connection), FastMCP creates a session
                            # but doesn't return the session_id. Try to extract it from FastMCP session manager
                            if method == "GET" and path == "/mcp" and status == 200 and not session_id_to_set:
                                # Check if Location header contains session_id first
                                location = headers_dict.get("location", headers_dict.get("Location", ""))
                                if location and "session_id=" in location:
                                    import urllib.parse
                                    parsed = urllib.parse.urlparse(location)
                                    params = urllib.parse.parse_qs(parsed.query)
                                    if "session_id" in params:
                                        session_id_to_set = params["session_id"][0]
                                        logger.info(f"[ASGI] Session ID from Location header: {session_id_to_set}")
                                
                                # If still no session_id, try to extract from FastMCP session manager
                                if not session_id_to_set:
                                    try:
                                        # FastMCP stores sessions internally - try to access them
                                        if hasattr(_mcp_instance, 'session_manager'):
                                            session_mgr = _mcp_instance.session_manager
                                            logger.debug(f"[ASGI] Session manager type: {type(session_mgr)}")
                                            # Try different ways to access sessions
                                            if hasattr(session_mgr, '_sessions'):
                                                sessions = session_mgr._sessions
                                                if sessions:
                                                    # Get most recent session ID
                                                    session_id_to_set = list(sessions.keys())[-1] if isinstance(sessions, dict) else None
                                                    if session_id_to_set:
                                                        logger.info(f"[ASGI] Extracted session_id from _sessions: {session_id_to_set}")
                                            elif hasattr(session_mgr, 'sessions'):
                                                sessions = session_mgr.sessions
                                                if sessions:
                                                    session_id_to_set = list(sessions.keys())[-1] if isinstance(sessions, dict) else None
                                                    if session_id_to_set:
                                                        logger.info(f"[ASGI] Extracted session_id from sessions: {session_id_to_set}")
                                    except Exception as e:
                                        logger.debug(f"[ASGI] Could not extract session_id from FastMCP: {e}")
                            
                            # If we have a session_id, add it to response headers
                            # OpenAI Agent Builder might expect it in X-Session-ID or Location header
                            if session_id_to_set:
                                # Add X-Session-ID header (commonly used by MCP clients)
                                if not any(k.lower() == b"x-session-id" for k, _ in headers_list):
                                    headers_list.append((b"x-session-id", session_id_to_set.encode("utf-8")))
                                    logger.info(f"[ASGI] Added X-Session-ID header: {session_id_to_set}")
                                
                                # Also set Location header if not present (standard for stateless HTTP)
                                if not any(k.lower() == b"location" for k, _ in headers_list):
                                    location_value = f"/mcp?session_id={session_id_to_set}"
                                    headers_list.append((b"location", location_value.encode("utf-8")))
                                    logger.info(f"[ASGI] Added Location header: {location_value}")
                            
                            # Log session-related headers if present
                            for key in ["x-session-id", "session-id", "location", "mcp-session-id", "set-cookie"]:
                                if key.lower() in {k.lower() for k in headers_dict.keys()}:
                                    logger.info(f"[ASGI] {key}: {headers_dict.get(key, headers_dict.get(key.lower(), 'N/A'))}")
                            
                            # Update message with potentially modified headers
                            message["headers"] = headers_list
                        
                        elif message.get("type") == "http.response.body":
                            # Collect body chunks for logging and potential session_id extraction
                            body_chunk = message.get("body", b"")
                            if body_chunk:
                                try:
                                    body_text = body_chunk.decode("utf-8", errors="ignore")
                                    if len(response_body_chunks) == 0:
                                        # First chunk - log it
                                        logger.info(f"[ASGI Response Body] (first 500 chars): {body_text[:500]}")
                                    
                                    # For SSE streams, check if session_id is in the stream
                                    # FastMCP might send it as: "id: session_id_value\n" or in JSON
                                    response_body_chunks.append(body_chunk)
                                    
                                    # Extract session_id from body if present (before first response is sent)
                                    nonlocal extracted_session_id
                                    if not extracted_session_id and (method == "GET" and path == "/mcp"):
                                        # Try to extract from SSE format: "id: session_id_value"
                                        for line in body_text.split("\n"):
                                            if line.startswith("id:") and len(line) > 4:
                                                session_id_candidate = line[4:].strip()
                                                # FastMCP session IDs are typically UUIDs (32+ chars)
                                                if len(session_id_candidate) > 20:
                                                    extracted_session_id = session_id_candidate
                                                    logger.info(f"[ASGI] Extracted session_id from SSE id: line: {extracted_session_id}")
                                                    break
                                            
                                            # Check for JSON in data: lines
                                            if line.startswith("data:"):
                                                try:
                                                    import json
                                                    json_str = line[5:].strip()
                                                    if json_str:
                                                        json_data = json.loads(json_str)
                                                        if isinstance(json_data, dict):
                                                            if "session_id" in json_data:
                                                                extracted_session_id = json_data["session_id"]
                                                                logger.info(f"[ASGI] Extracted session_id from SSE data: {extracted_session_id}")
                                                                break
                                                            # Also check in nested result
                                                            if "result" in json_data and isinstance(json_data["result"], dict):
                                                                if "session_id" in json_data["result"]:
                                                                    extracted_session_id = json_data["result"]["session_id"]
                                                                    logger.info(f"[ASGI] Extracted session_id from result: {extracted_session_id}")
                                                                    break
                                                except:
                                                    pass
                                        
                                        # If we found a session_id, we need to add it to headers
                                        # But headers are already sent, so we can't modify them here
                                        # Instead, we'll log it and the client should extract it from body
                                        if extracted_session_id:
                                            logger.info(f"[ASGI] Session ID found in body: {extracted_session_id} (client should extract from body)")
                                            
                                except Exception as e:
                                    logger.debug(f"[ASGI] Error parsing body: {e}")
                        
                        await send(message)
                    
                    await original_asgi_app(scope, receive, send_wrapper)
                else:
                    await original_asgi_app(scope, receive, send)
            
            # Call original Config.__init__ with wrapped app
            # Remove allowed_hosts from kwargs if present (uvicorn.Config doesn't accept it directly)
            kwargs.pop("allowed_hosts", None)
            kwargs.setdefault("server_header", False)
            original_config_init(self, wrapped_asgi_app, *args, **kwargs)
            # Set allowed_hosts after initialization to accept all hosts for ngrok
            if hasattr(self, "allowed_hosts"):
                self.allowed_hosts = ["*"]
            # Also try to disable host checking via app settings
            if hasattr(self, "app") and hasattr(self.app, "state"):
                # Try to disable host checking in Starlette app
                pass
        
        # Patch Config before running
        uvicorn.Config.__init__ = patched_config_init
        
        try:
            # Using streamable-http transport with stateless_http=True (configured in server.py)
            # This enables stateless session management via session_id in query parameters
            # Compatible with OpenAI Agent Builder and multiple clients/load balancers
            mcp.run(transport="streamable-http")
        finally:
            # Restore original Config.__init__
            uvicorn.Config.__init__ = original_config_init
    except KeyboardInterrupt:
        print("\nServer shutdown requested...")
        sys.exit(0)


if __name__ == "__main__":
    main()
