from __future__ import annotations

import ipaddress
import socket
import time
from html.parser import HTMLParser
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP

class _TextHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_script = False
        self._in_style = False
        self._in_title = False
        self.title: str = ""
        self._parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "script":
            self._in_script = True
        if t == "style":
            self._in_style = True
        if t == "title":
            self._in_title = True
        if t in {"p","br","div","li","h1","h2","h3","h4","h5","h6"}:
            self._parts.append("\n")

    def handle_endtag(self, tag):
        t = tag.lower()
        if t == "script":
            self._in_script = False
        if t == "style":
            self._in_style = False
        if t == "title":
            self._in_title = False
        if t in {"p","div","li","h1","h2","h3","h4","h5","h6"}:
            self._parts.append("\n")

    def handle_data(self, data):
        if self._in_script or self._in_style:
            return
        s = (data or "").strip()
        if not s:
            return
        if self._in_title and not self.title:
            self.title = s[:200]
            return
        self._parts.append(s)

    def text(self) -> str:
        out = "\n".join(self._parts)
        while "\n\n\n" in out:
            out = out.replace("\n\n\n", "\n\n")
        return out.strip()

def _is_blocked_host(host: str, port: int) -> Optional[str]:
    """
    Prüft ob Host/IP blockiert ist (SSRF Protection).
    
    Security: Blockiert private IPs, localhost, etc.
    """
    h = (host or "").strip().lower()
    if h in {"localhost"}:
        return "blocked hostname"
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return "dns resolution failed"
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except Exception:
            return "invalid ip"
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return f"blocked ip {ip}"
    return None


def _validate_redirect_url(url: str, original_url: str) -> Optional[str]:
    """
    Validiert Redirect-URL gegen SSRF-Schutz.
    
    Security: Jede Redirect-URL muss erneut validiert werden,
    um SSRF-Bypass durch Redirects zu verhindern.
    
    Args:
        url: Die Redirect-URL (kann relativ sein)
        original_url: Die ursprüngliche URL (für relative Redirects)
        
    Returns:
        None wenn URL sicher ist, Fehlermeldung sonst
    """
    # Relative URLs auflösen
    if url.startswith("/"):
        # Relative zum Original-Host
        parsed_original = urlparse(original_url)
        url = f"{parsed_original.scheme}://{parsed_original.netloc}{url}"
    elif not url.startswith(("http://", "https://")):
        # Relative Path
        parsed_original = urlparse(original_url)
        url = f"{parsed_original.scheme}://{parsed_original.netloc}/{url.lstrip('/')}"
    
    # URL parsen
    u = urlparse(url)
    if u.scheme not in {"http", "https"}:
        return "only http/https allowed"
    
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    
    # SSRF-Protection: Host/IP prüfen
    return _is_blocked_host(host, port)

def register_website_fetch_tools(mcp: FastMCP) -> None:
    @mcp.tool(name="website.fetch", description="Fetch a public URL and return extracted text (SSRF-protected, size-limited).")
    async def website_fetch(
        url: str,
        max_chars: int = 20000,
        timeout_seconds: float = 20.0,
        user_agent: str = "SimpleGPT-Fetcher/1.0",
        ctx: Any = None,
    ) -> Dict[str, Any]:
        u = urlparse(url)
        if u.scheme not in {"http", "https"}:
            return {"error": "only http/https allowed", "url": url}
        host = u.hostname or ""
        port = u.port or (443 if u.scheme == "https" else 80)
        blocked = _is_blocked_host(host, port)
        if blocked:
            return {"error": f"blocked url ({blocked})", "url": url}
        headers = {"User-Agent": user_agent}
        buf = bytearray()
        truncated = False
        
        # Security: Manuelles Redirect-Following mit Validierung
        # follow_redirects=False, damit wir jede Redirect-URL validieren können
        max_redirects = 5
        current_url = url
        redirect_count = 0
        
        async with httpx.AsyncClient(follow_redirects=False, headers=headers, timeout=httpx.Timeout(timeout_seconds)) as client:
            while redirect_count < max_redirects:
                async with client.stream("GET", current_url) as resp:
                    # Redirect-Status-Codes (3xx)
                    if resp.status_code in {301, 302, 303, 307, 308}:
                        redirect_count += 1
                        location = resp.headers.get("location") or resp.headers.get("Location")
                        if not location:
                            return {"error": "redirect without location header", "url": current_url}
                        
                        # Security: Redirect-URL validieren
                        redirect_error = _validate_redirect_url(location, current_url)
                        if redirect_error:
                            return {"error": f"blocked redirect url ({redirect_error})", "url": location, "original_url": url}
                        
                        # Relative URLs auflösen
                        if location.startswith("/"):
                            parsed_current = urlparse(current_url)
                            current_url = f"{parsed_current.scheme}://{parsed_current.netloc}{location}"
                        elif not location.startswith(("http://", "https://")):
                            parsed_current = urlparse(current_url)
                            current_url = f"{parsed_current.scheme}://{parsed_current.netloc}/{location.lstrip('/')}"
                        else:
                            current_url = location
                        
                        # Weiter mit Redirect
                        continue
                    
                    # Nicht-Redirect: Daten lesen
                    ctype = resp.headers.get("content-type", "")
                    async for chunk in resp.aiter_bytes():
                        if not chunk:
                            continue
                        remain = (1024 * 1024) - len(buf)
                        if remain <= 0:
                            truncated = True
                            break
                        buf.extend(chunk[:remain])
                        if len(buf) >= 1024 * 1024:
                            truncated = True
                            break
                    raw = bytes(buf)
                    text = ""
                    title = ""
                    if "html" in (ctype or "").lower():
                        parser = _TextHTMLParser()
                        try:
                            parser.feed(raw.decode("utf-8", errors="replace"))
                        except Exception:
                            parser.feed(str(raw))
                        text = parser.text()
                        title = parser.title
                    else:
                        text = raw.decode("utf-8", errors="replace")
                    if len(text) > max_chars:
                        text = text[:max_chars]
                        truncated = True
                    return {
                        "url": url,
                        "final_url": str(resp.url),
                        "status_code": resp.status_code,
                        "content_type": ctype,
                        "title": title,
                        "text": text,
                        "truncated": truncated,
                        "fetched_at": int(time.time()),
                    }
            
            # Zu viele Redirects
            return {"error": f"too many redirects (>{max_redirects})", "url": current_url, "original_url": url}
