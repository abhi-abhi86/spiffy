"""
Redis Cache Manager for Spiffy Security Suite
High-performance caching for scan results and network data
"""

import redis
import json
import hashlib
import pickle
from typing import Optional, Any, Dict, List, Callable
from datetime import timedelta
from functools import wraps
import time

class CacheManager:
    """
    Redis-based caching with:
    - TTL-based expiration
    - Pattern-based invalidation
    - Cache statistics
    - Automatic serialization
    """
    
    def __init__(self, host='localhost', port=6379, db=0, enabled=True):
        self.enabled = enabled
        self.redis_client = None
        
        if enabled:
            try:
                self.redis_client = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    decode_responses=False,  # Handle binary data
                    socket_connect_timeout=2,
                    socket_timeout=2
                )
                # Test connection
                self.redis_client.ping()
                print(f"✓ Redis cache connected ({host}:{port})")
            except Exception as e:
                print(f"⚠️  Redis not available: {e}")
                print("   Caching disabled - install Redis or set enabled=False")
                self.enabled = False
                self.redis_client = None
    
    def _make_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from prefix and arguments"""
        # Combine all arguments into a string
        key_parts = [str(prefix)]
        key_parts.extend(str(arg) for arg in args)
        key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
        
        key_data = ":".join(key_parts)
        
        # Hash for consistent length
        key_hash = hashlib.sha256(key_data.encode()).hexdigest()[:16]
        return f"spiffy:{prefix}:{key_hash}"
    
    def get(self, prefix: str, *args, **kwargs) -> Optional[Any]:
        """Get cached value"""
        if not self.enabled or not self.redis_client:
            return None
        
        key = self._make_key(prefix, *args, **kwargs)
        
        try:
            data = self.redis_client.get(key)
            if data:
                return pickle.loads(data)
        except Exception as e:
            print(f"Cache get error: {e}")
        
        return None
    
    def set(self, prefix: str, value: Any, ttl: int = 3600, *args, **kwargs):
        """
        Set cached value with TTL
        
        Args:
            prefix: Cache key prefix
            value: Value to cache
            ttl: Time to live in seconds (default: 1 hour)
            *args, **kwargs: Additional key components
        """
        if not self.enabled or not self.redis_client:
            return
        
        key = self._make_key(prefix, *args, **kwargs)
        
        try:
            data = pickle.dumps(value)
            self.redis_client.setex(key, ttl, data)
        except Exception as e:
            print(f"Cache set error: {e}")
    
    def delete(self, prefix: str, *args, **kwargs):
        """Delete specific cache entry"""
        if not self.enabled or not self.redis_client:
            return
        
        key = self._make_key(prefix, *args, **kwargs)
        
        try:
            self.redis_client.delete(key)
        except Exception as e:
            print(f"Cache delete error: {e}")
    
    def invalidate_pattern(self, pattern: str):
        """
        Invalidate all keys matching pattern
        
        Args:
            pattern: Redis pattern (e.g., "spiffy:portscan:*")
        """
        if not self.enabled or not self.redis_client:
            return
        
        try:
            keys = list(self.redis_client.scan_iter(match=pattern))
            if keys:
                self.redis_client.delete(*keys)
                return len(keys)
        except Exception as e:
            print(f"Cache invalidate error: {e}")
        
        return 0
    
    def get_or_compute(self, prefix: str, compute_fn: Callable, 
                      ttl: int = 3600, *args, **kwargs) -> Any:
        """
        Get from cache or compute and cache
        
        Args:
            prefix: Cache key prefix
            compute_fn: Function to compute value if not cached
            ttl: Time to live in seconds
            *args, **kwargs: Additional key components
        
        Returns:
            Cached or computed value
        """
        # Try cache first
        cached = self.get(prefix, *args, **kwargs)
        if cached is not None:
            return cached
        
        # Compute value
        value = compute_fn()
        
        # Cache it
        self.set(prefix, value, ttl, *args, **kwargs)
        
        return value
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if not self.enabled or not self.redis_client:
            return {
                "enabled": False,
                "status": "disabled"
            }
        
        try:
            info = self.redis_client.info()
            
            hits = info.get('keyspace_hits', 0)
            misses = info.get('keyspace_misses', 0)
            total = hits + misses
            hit_rate = (hits / total * 100) if total > 0 else 0.0
            
            return {
                "enabled": True,
                "status": "connected",
                "used_memory": info.get('used_memory_human', 'N/A'),
                "total_keys": self.redis_client.dbsize(),
                "hits": hits,
                "misses": misses,
                "hit_rate": round(hit_rate, 2),
                "connected_clients": info.get('connected_clients', 0),
                "uptime_seconds": info.get('uptime_in_seconds', 0)
            }
        except Exception as e:
            return {
                "enabled": True,
                "status": "error",
                "error": str(e)
            }
    
    def flush_all(self):
        """Clear all cache (use with caution!)"""
        if not self.enabled or not self.redis_client:
            return
        
        try:
            self.redis_client.flushdb()
            print("✓ Cache flushed")
        except Exception as e:
            print(f"Cache flush error: {e}")
    
    def close(self):
        """Close Redis connection"""
        if self.redis_client:
            try:
                self.redis_client.close()
            except:
                pass


# Decorator for caching function results
def cached(prefix: str, ttl: int = 3600):
    """
    Decorator to cache function results
    
    Usage:
        @cached("my_function", ttl=300)
        def expensive_function(arg1, arg2):
            # ... expensive computation
            return result
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get cache manager from global or create one
            cache = getattr(wrapper, '_cache', None)
            if cache is None:
                cache = CacheManager()
                wrapper._cache = cache
            
            # Try cache
            cached_result = cache.get(prefix, *args, **kwargs)
            if cached_result is not None:
                return cached_result
            
            # Compute and cache
            result = func(*args, **kwargs)
            cache.set(prefix, result, ttl, *args, **kwargs)
            
            return result
        
        return wrapper
    return decorator


# Specialized cache managers for different data types
class ScanResultCache:
    """Specialized cache for scan results"""
    
    def __init__(self, cache: CacheManager):
        self.cache = cache
        self.default_ttl = 3600  # 1 hour
    
    def get_port_scan(self, ip: str) -> Optional[List[int]]:
        """Get cached port scan results"""
        return self.cache.get("portscan", ip=ip)
    
    def set_port_scan(self, ip: str, open_ports: List[int], ttl: Optional[int] = None):
        """Cache port scan results"""
        self.cache.set("portscan", open_ports, ttl or self.default_ttl, ip=ip)
    
    def get_vuln_scan(self, target: str) -> Optional[List[str]]:
        """Get cached vulnerability scan results"""
        return self.cache.get("vulnscan", target=target)
    
    def set_vuln_scan(self, target: str, findings: List[str], ttl: Optional[int] = None):
        """Cache vulnerability scan results"""
        self.cache.set("vulnscan", findings, ttl or self.default_ttl, target=target)
    
    def get_network_topology(self, subnet: str) -> Optional[Dict]:
        """Get cached network topology"""
        return self.cache.get("topology", subnet=subnet)
    
    def set_network_topology(self, subnet: str, topology: Dict, ttl: Optional[int] = None):
        """Cache network topology"""
        self.cache.set("topology", topology, ttl or self.default_ttl, subnet=subnet)
    
    def invalidate_host(self, ip: str):
        """Invalidate all cache entries for a host"""
        self.cache.invalidate_pattern(f"spiffy:*:*{ip}*")


if __name__ == "__main__":
    # Test the cache manager
    print("Testing Redis Cache Manager...")
    
    cache = CacheManager()
    
    if cache.enabled:
        print("\n1. Testing basic get/set...")
        cache.set("test", {"data": "hello world"}, ttl=60)
        result = cache.get("test")
        print(f"   Cached value: {result}")
        
        print("\n2. Testing get_or_compute...")
        def expensive_computation():
            print("   Computing expensive result...")
            time.sleep(0.1)
            return [1, 2, 3, 4, 5]
        
        result1 = cache.get_or_compute("compute_test", expensive_computation, ttl=60)
        print(f"   First call (computed): {result1}")
        
        result2 = cache.get_or_compute("compute_test", expensive_computation, ttl=60)
        print(f"   Second call (cached): {result2}")
        
        print("\n3. Testing specialized cache...")
        scan_cache = ScanResultCache(cache)
        scan_cache.set_port_scan("192.168.1.1", [22, 80, 443])
        ports = scan_cache.get_port_scan("192.168.1.1")
        print(f"   Cached ports: {ports}")
        
        print("\n4. Cache statistics:")
        stats = cache.get_stats()
        for key, value in stats.items():
            print(f"   {key}: {value}")
        
        # Cleanup
        cache.delete("test")
        cache.close()
    else:
        print("✗ Redis not available")
        print("  Install Redis: brew install redis (macOS) or apt-get install redis (Linux)")
        print("  Start Redis: redis-server")
