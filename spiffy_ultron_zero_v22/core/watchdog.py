#!/usr/bin/env python3
"""
Watchdog System - Enforces timeouts on all network operations
Prevents hanging on slow/unresponsive nodes
"""

import asyncio
import functools
from typing import Callable, Any, Optional
import time


class WatchdogEnforcer:
    """
    Enforces strict timeouts on all async operations
    Default timeout: 1.5 seconds (WATCHDOG_TIMEOUT)
    """
    
    DEFAULT_TIMEOUT = 1.5
    
    def __init__(self, default_timeout: float = DEFAULT_TIMEOUT):
        """
        Initialize watchdog enforcer
        
        Args:
            default_timeout: Default timeout in seconds
        """
        self.default_timeout = default_timeout
        self.timeout_count = 0
        self.total_operations = 0
        
    async def enforce(self, coro, timeout: Optional[float] = None) -> Any:
        """
        Enforce timeout on an async operation
        
        Args:
            coro: Coroutine to execute
            timeout: Optional custom timeout (uses default if None)
            
        Returns:
            Result of the coroutine
            
        Raises:
            asyncio.TimeoutError: If operation exceeds timeout
        """
        self.total_operations += 1
        timeout_value = timeout if timeout is not None else self.default_timeout
        
        try:
            result = await asyncio.wait_for(coro, timeout=timeout_value)
            return result
        except asyncio.TimeoutError:
            self.timeout_count += 1
            raise
    
    def watchdog(self, timeout: Optional[float] = None):
        """
        Decorator to enforce timeout on async functions
        
        Args:
            timeout: Optional custom timeout
            
        Example:
            @watchdog.watchdog(timeout=2.0)
            async def scan_port(ip, port):
                # This will timeout after 2.0 seconds
                ...
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                coro = func(*args, **kwargs)
                return await self.enforce(coro, timeout)
            return wrapper
        return decorator
    
    def get_stats(self) -> dict:
        """Get watchdog statistics"""
        success_rate = ((self.total_operations - self.timeout_count) / 
                       self.total_operations * 100) if self.total_operations > 0 else 100
        
        return {
            "total_operations": self.total_operations,
            "timeout_count": self.timeout_count,
            "success_count": self.total_operations - self.timeout_count,
            "success_rate": round(success_rate, 2),
            "default_timeout": self.default_timeout
        }
    
    def reset_stats(self):
        """Reset watchdog statistics"""
        self.timeout_count = 0
        self.total_operations = 0


class RetryStrategy:
    """
    Implements exponential backoff retry strategy
    """
    
    @staticmethod
    async def retry_with_backoff(
        coro_func: Callable,
        max_retries: int = 3,
        base_delay: float = 0.1,
        max_delay: float = 2.0,
        *args,
        **kwargs
    ) -> Any:
        """
        Retry an async operation with exponential backoff
        
        Args:
            coro_func: Async function to retry
            max_retries: Maximum number of retry attempts
            base_delay: Initial delay between retries
            max_delay: Maximum delay between retries
            *args, **kwargs: Arguments to pass to coro_func
            
        Returns:
            Result of successful operation
            
        Raises:
            Exception: Last exception if all retries fail
        """
        last_exception = None
        
        for attempt in range(max_retries):
            try:
                return await coro_func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt < max_retries - 1:
                    # Calculate exponential backoff delay
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    await asyncio.sleep(delay)
        
        # All retries failed
        raise last_exception


# Global watchdog instance
watchdog = WatchdogEnforcer()


# Convenience decorator
def enforce_timeout(timeout: Optional[float] = None):
    """
    Convenience decorator for timeout enforcement
    
    Example:
        @enforce_timeout(1.5)
        async def my_network_call():
            ...
    """
    return watchdog.watchdog(timeout)


if __name__ == "__main__":
    # Test watchdog enforcement
    async def test_fast_operation():
        """Should complete successfully"""
        await asyncio.sleep(0.5)
        return "Success"
    
    async def test_slow_operation():
        """Should timeout"""
        await asyncio.sleep(3.0)
        return "This won't be reached"
    
    async def main():
        wd = WatchdogEnforcer(timeout=1.0)
        
        # Test fast operation
        try:
            result = await wd.enforce(test_fast_operation())
            print(f"✓ Fast operation: {result}")
        except asyncio.TimeoutError:
            print("✗ Fast operation timed out (unexpected)")
        
        # Test slow operation
        try:
            result = await wd.enforce(test_slow_operation())
            print(f"✗ Slow operation completed (unexpected): {result}")
        except asyncio.TimeoutError:
            print("✓ Slow operation timed out (expected)")
        
        # Print stats
        print(f"\nWatchdog Stats: {wd.get_stats()}")
    
    asyncio.run(main())
