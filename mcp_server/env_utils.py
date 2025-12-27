"""
Environment Utilities - Production mode detection.

P0 Fix: Konsistente Production-Modus-Erkennung.
"""
from __future__ import annotations

import os


def is_production_env() -> bool:
    """
    Prüft, ob die App im Production-Modus läuft.
    
    Returns True wenn:
    - ENVIRONMENT=production
    - APP_ENV=production
    - NODE_ENV=production
    
    (case-insensitive, nach lowercase + strip)
    
    Returns:
        True wenn Production-Modus, sonst False
    """
    env_vars = [
        os.getenv("ENVIRONMENT", ""),
        os.getenv("APP_ENV", ""),
        os.getenv("NODE_ENV", ""),
    ]
    
    for env_val in env_vars:
        if env_val.strip().lower() == "production":
            return True
    
    return False

