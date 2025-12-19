#!/usr/bin/env python3
"""
Omega Kernel - Performance Monitor
Tracks system performance and provides metrics
"""

import time
import psutil
import asyncio
from typing import Dict, Any, Callable
from functools import wraps
from collections import deque
from datetime import datetime

class PerformanceMonitor:
    """Monitor and track performance metrics"""
    
    def __init__(self, history_size: int = 1000):
        self.metrics = {
            'scan_times': deque(maxlen=history_size),
            'api_calls': deque(maxlen=history_size),
            'memory_usage': deque(maxlen=history_size),
            'cpu_usage': deque(maxlen=history_size)
        }
        self.start_time = time.time()
    
    def track_operation(self, operation_name: str):
        """Decorator to track operation performance"""
        def decorator(func: Callable):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start = time.time()
                try:
                    result = await func(*args, **kwargs)
                    duration = (time.time() - start) * 1000  # ms
                    self.record_metric(operation_name, duration)
                    return result
                except Exception as e:
                    duration = (time.time() - start) * 1000
                    self.record_metric(f"{operation_name}_error", duration)
                    raise
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start = time.time()
                try:
                    result = func(*args, **kwargs)
                    duration = (time.time() - start) * 1000  # ms
                    self.record_metric(operation_name, duration)
                    return result
                except Exception as e:
                    duration = (time.time() - start) * 1000
                    self.record_metric(f"{operation_name}_error", duration)
                    raise
            
            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
        return decorator
    
    def record_metric(self, name: str, value: float):
        """Record a performance metric"""
        if name not in self.metrics:
            self.metrics[name] = deque(maxlen=1000)
        
        self.metrics[name].append({
            'timestamp': datetime.now().isoformat(),
            'value': value
        })
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Get current system statistics"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_used_mb': psutil.virtual_memory().used / (1024 * 1024),
            'disk_usage_percent': psutil.disk_usage('/').percent,
            'uptime_seconds': time.time() - self.start_time
        }
    
    def get_operation_stats(self, operation_name: str) -> Dict[str, Any]:
        """Get statistics for a specific operation"""
        if operation_name not in self.metrics or not self.metrics[operation_name]:
            return {}
        
        values = [m['value'] for m in self.metrics[operation_name]]
        
        return {
            'count': len(values),
            'avg_ms': sum(values) / len(values),
            'min_ms': min(values),
            'max_ms': max(values),
            'last_ms': values[-1] if values else 0
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get overall performance summary"""
        system_stats = self.get_system_stats()
        
        operation_stats = {}
        for op_name in self.metrics:
            if self.metrics[op_name]:
                operation_stats[op_name] = self.get_operation_stats(op_name)
        
        return {
            'system': system_stats,
            'operations': operation_stats,
            'uptime_hours': system_stats['uptime_seconds'] / 3600
        }

# Global performance monitor
perf_monitor = PerformanceMonitor()
