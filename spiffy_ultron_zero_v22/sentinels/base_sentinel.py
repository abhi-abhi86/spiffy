#!/usr/bin/env python3
"""
Base Sentinel Class for Omega Kernel
All security modules inherit from this base class
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime


class BaseSentinel(ABC):
    """Abstract base class for all Omega Kernel sentinels"""
    
    def __init__(self, name: str, sentinel_type: str):
        """
        Initialize base sentinel
        
        Args:
            name: Sentinel module name
            sentinel_type: Type (OFFENSIVE, DEFENSIVE, UTILITY)
        """
        self.name = name
        self.sentinel_type = sentinel_type
        self.enabled = True
        self.last_run = None
        self.run_count = 0
        self.error_count = 0
        
    @abstractmethod
    async def execute(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute the sentinel's primary function
        
        Returns:
            Dict containing execution results
        """
        pass
    
    @abstractmethod
    def validate_input(self, *args, **kwargs) -> bool:
        """
        Validate input parameters before execution
        
        Returns:
            True if valid, False otherwise
        """
        pass
    
    async def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Wrapper method that handles execution with error handling
        
        Returns:
            Dict containing results or error information
        """
        if not self.enabled:
            return {
                "status": "disabled",
                "sentinel": self.name,
                "message": "Sentinel is currently disabled"
            }
        
        if not self.validate_input(*args, **kwargs):
            return {
                "status": "error",
                "sentinel": self.name,
                "message": "Input validation failed"
            }
        
        try:
            self.last_run = datetime.now()
            self.run_count += 1
            
            result = await self.execute(*args, **kwargs)
            
            return {
                "status": "success",
                "sentinel": self.name,
                "type": self.sentinel_type,
                "timestamp": self.last_run.isoformat(),
                "data": result
            }
            
        except asyncio.TimeoutError:
            self.error_count += 1
            return {
                "status": "timeout",
                "sentinel": self.name,
                "message": "Operation timed out (watchdog enforced)"
            }
            
        except Exception as e:
            self.error_count += 1
            return {
                "status": "error",
                "sentinel": self.name,
                "message": str(e),
                "error_type": type(e).__name__
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get sentinel statistics"""
        return {
            "name": self.name,
            "type": self.sentinel_type,
            "enabled": self.enabled,
            "run_count": self.run_count,
            "error_count": self.error_count,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "success_rate": ((self.run_count - self.error_count) / self.run_count * 100) if self.run_count > 0 else 0
        }
    
    def enable(self):
        """Enable this sentinel"""
        self.enabled = True
    
    def disable(self):
        """Disable this sentinel"""
        self.enabled = False
    
    def reset_stats(self):
        """Reset sentinel statistics"""
        self.run_count = 0
        self.error_count = 0
        self.last_run = None
