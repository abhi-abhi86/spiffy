#!/usr/bin/env python3
"""
Omega Kernel - Error Handler
Comprehensive error handling and recovery
"""

import sys
import traceback
from typing import Callable, Any, Optional
from functools import wraps
import asyncio

class OmegaErrorHandler:
    """Centralized error handling and recovery"""
    
    def __init__(self):
        self.error_count = {}
        self.recovery_strategies = {}
    
    def handle_error(self, module: str, error: Exception, context: dict = None) -> Optional[str]:
        """Handle an error with appropriate recovery strategy"""
        error_type = type(error).__name__
        
        # Track error count
        key = f"{module}:{error_type}"
        self.error_count[key] = self.error_count.get(key, 0) + 1
        
        # Get recovery strategy
        if key in self.recovery_strategies:
            return self.recovery_strategies[key](error, context)
        
        # Default error messages with solutions
        return self._get_error_solution(error_type, error)
    
    def _get_error_solution(self, error_type: str, error: Exception) -> str:
        """Get user-friendly error message with solution"""
        solutions = {
            'ConnectionRefusedError': "❌ Connection refused. Check if the target is online and firewall allows connections.",
            'TimeoutError': "⏱️ Operation timed out. The target may be slow or unreachable.",
            'PermissionError': "🔒 Permission denied. Try running with sudo/administrator privileges.",
            'FileNotFoundError': f"📁 File not found: {error}. Check the file path.",
            'ValueError': f"⚠️ Invalid value: {error}. Check your input format.",
            'KeyboardInterrupt': "⛔ Operation cancelled by user.",
            'OSError': f"💻 System error: {error}. Check system resources.",
        }
        
        return solutions.get(error_type, f"❌ {error_type}: {error}")
    
    def safe_execute(self, func: Callable, *args, **kwargs) -> tuple[bool, Any]:
        """Execute function with error handling"""
        try:
            result = func(*args, **kwargs)
            return (True, result)
        except Exception as e:
            error_msg = self.handle_error(func.__name__, e)
            print(f"\n{error_msg}\n")
            return (False, None)
    
    async def safe_execute_async(self, coro, module: str = "async") -> tuple[bool, Any]:
        """Execute async function with error handling"""
        try:
            result = await coro
            return (True, result)
        except Exception as e:
            error_msg = self.handle_error(module, e)
            print(f"\n{error_msg}\n")
            return (False, None)
    
    def with_retry(self, max_retries: int = 3, delay: float = 1.0):
        """Decorator for automatic retry on failure"""
        def decorator(func: Callable):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                last_error = None
                for attempt in range(max_retries):
                    try:
                        return await func(*args, **kwargs)
                    except Exception as e:
                        last_error = e
                        if attempt < max_retries - 1:
                            await asyncio.sleep(delay * (attempt + 1))
                
                # All retries failed
                raise last_error
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                last_error = None
                for attempt in range(max_retries):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        last_error = e
                        if attempt < max_retries - 1:
                            import time
                            time.sleep(delay * (attempt + 1))
                
                raise last_error
            
            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
        return decorator
    
    def get_error_stats(self) -> dict:
        """Get error statistics"""
        return {
            'total_errors': sum(self.error_count.values()),
            'error_breakdown': dict(self.error_count),
            'most_common': max(self.error_count.items(), key=lambda x: x[1]) if self.error_count else None
        }

# Global error handler
error_handler = OmegaErrorHandler()
