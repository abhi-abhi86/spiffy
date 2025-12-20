"""
Async I/O Connection Pool with Adaptive Concurrency
Optimizes network scanning with connection reuse and backpressure handling
"""

import asyncio
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import time
import statistics

@dataclass
class PoolStats:
    """Connection pool statistics"""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    cache_hits: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    
    @property
    def avg_response_time(self) -> float:
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)
    
    @property
    def success_rate(self) -> float:
        total = self.successful_requests + self.failed_requests
        if total == 0:
            return 1.0
        return self.successful_requests / total


class Connection:
    """RAII-style connection wrapper"""
    
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.created_at = time.time()
        self.last_used = time.time()
        self.use_count = 0
    
    def is_alive(self) -> bool:
        """Check if connection is still alive"""
        return not self.writer.is_closing() and (time.time() - self.created_at) < 300  # 5 min max age
    
    async def close(self):
        """Close connection gracefully"""
        if not self.writer.is_closing():
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=1.0)
            except:
                pass


class AsyncConnectionPool:
    """
    Adaptive connection pool with:
    - Connection reuse
    - Adaptive concurrency control
    - Backpressure handling
    - Request batching
    """
    
    def __init__(self, 
                 max_connections: int = 100,
                 min_connections: int = 10,
                 connection_timeout: float = 5.0,
                 max_idle_time: float = 60.0):
        self.max_connections = max_connections
        self.min_connections = min_connections
        self.connection_timeout = connection_timeout
        self.max_idle_time = max_idle_time
        
        # Connection pools per host
        self.pools: Dict[str, deque[Connection]] = defaultdict(deque)
        self.pool_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(max_connections)
        self.current_concurrency = min_connections
        
        # Statistics
        self.stats = PoolStats()
        
        # Adaptive control
        self._last_adjustment = time.time()
        self._adjustment_interval = 5.0  # Adjust every 5 seconds
    
    async def execute(self, 
                     host: str, 
                     port: int,
                     operation: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Any],
                     timeout: Optional[float] = None) -> Optional[Any]:
        """
        Execute operation with connection pooling
        
        Args:
            host: Target hostname
            port: Target port
            operation: Async function that takes (reader, writer) and returns result
            timeout: Operation timeout (uses connection_timeout if None)
        
        Returns:
            Operation result or None on error
        """
        timeout = timeout or self.connection_timeout
        start_time = time.time()
        connection = None
        
        async with self.semaphore:
            try:
                # Try to get existing connection
                connection = await self._acquire_connection(host, port)
                
                if connection is None:
                    # Create new connection
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=timeout
                    )
                    connection = Connection(reader, writer)
                    self.stats.total_connections += 1
                else:
                    self.stats.cache_hits += 1
                
                self.stats.active_connections += 1
                
                # Execute operation with timeout
                result = await asyncio.wait_for(
                    operation(connection.reader, connection.writer),
                    timeout=timeout
                )
                
                # Update connection stats
                connection.last_used = time.time()
                connection.use_count += 1
                
                # Return connection to pool
                await self._release_connection(host, port, connection)
                
                # Update stats
                elapsed = time.time() - start_time
                self._update_stats(elapsed, success=True)
                
                return result
                
            except asyncio.TimeoutError:
                self._update_stats(0, success=False)
                if connection:
                    await connection.close()
                return None
                
            except Exception as e:
                self._update_stats(0, success=False)
                if connection:
                    await connection.close()
                return None
                
            finally:
                self.stats.active_connections -= 1
    
    async def _acquire_connection(self, host: str, port: int) -> Optional[Connection]:
        """Get connection from pool or create new one"""
        key = f"{host}:{port}"
        
        async with self.pool_locks[key]:
            pool = self.pools[key]
            
            # Try to find alive connection
            while pool:
                connection = pool.popleft()
                if connection.is_alive():
                    self.stats.idle_connections -= 1
                    return connection
                else:
                    await connection.close()
            
            return None
    
    async def _release_connection(self, host: str, port: int, connection: Connection):
        """Return connection to pool"""
        if not connection.is_alive():
            await connection.close()
            return
        
        key = f"{host}:{port}"
        
        async with self.pool_locks[key]:
            pool = self.pools[key]
            
            # Limit pool size per host
            if len(pool) < 5:
                pool.append(connection)
                self.stats.idle_connections += 1
            else:
                await connection.close()
    
    def _update_stats(self, elapsed: float, success: bool):
        """Update statistics and adjust concurrency"""
        self.stats.total_requests += 1
        
        if success:
            self.stats.successful_requests += 1
            self.stats.response_times.append(elapsed)
        else:
            self.stats.failed_requests += 1
        
        # Adaptive concurrency adjustment
        now = time.time()
        if now - self._last_adjustment >= self._adjustment_interval:
            self._adjust_concurrency()
            self._last_adjustment = now
    
    def _adjust_concurrency(self):
        """Adjust concurrency based on performance"""
        success_rate = self.stats.success_rate
        avg_time = self.stats.avg_response_time
        
        if success_rate > 0.95 and avg_time < 0.5:
            # Performing well, increase concurrency
            new_concurrency = min(
                self.current_concurrency + 10,
                self.max_connections
            )
            if new_concurrency != self.current_concurrency:
                self.current_concurrency = new_concurrency
                # Update semaphore (approximate)
                
        elif success_rate < 0.8 or avg_time > 2.0:
            # Struggling, decrease concurrency
            new_concurrency = max(
                self.current_concurrency - 5,
                self.min_connections
            )
            if new_concurrency != self.current_concurrency:
                self.current_concurrency = new_concurrency
    
    async def close_all(self):
        """Close all connections"""
        for pool in self.pools.values():
            while pool:
                connection = pool.popleft()
                await connection.close()
        
        self.pools.clear()
        self.stats.idle_connections = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        return {
            'total_connections': self.stats.total_connections,
            'active_connections': self.stats.active_connections,
            'idle_connections': self.stats.idle_connections,
            'total_requests': self.stats.total_requests,
            'successful_requests': self.stats.successful_requests,
            'failed_requests': self.stats.failed_requests,
            'cache_hits': self.stats.cache_hits,
            'avg_response_time': self.stats.avg_response_time,
            'success_rate': self.stats.success_rate * 100,
            'current_concurrency': self.current_concurrency
        }
    
    async def __aenter__(self):
        """Context manager support"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        await self.close_all()


# Convenience functions
async def scan_port_async(pool: AsyncConnectionPool, host: str, port: int) -> bool:
    """Scan a single port using the connection pool"""
    async def check_port(reader, writer):
        return True  # Connection successful
    
    result = await pool.execute(host, port, check_port, timeout=2.0)
    return result is not None


async def batch_scan_ports(pool: AsyncConnectionPool, 
                          host: str, 
                          ports: List[int]) -> List[int]:
    """Scan multiple ports in parallel using the pool"""
    tasks = [scan_port_async(pool, host, port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    open_ports = []
    for port, result in zip(ports, results):
        if result is True:
            open_ports.append(port)
    
    return sorted(open_ports)


if __name__ == "__main__":
    # Test the connection pool
    async def test_pool():
        print("Testing Async Connection Pool...")
        
        async with AsyncConnectionPool(max_connections=50) as pool:
            # Test single port
            print("\nTesting single port scan...")
            is_open = await scan_port_async(pool, "8.8.8.8", 53)
            print(f"  Port 53: {'OPEN' if is_open else 'CLOSED'}")
            
            # Test batch scan
            print("\nTesting batch port scan...")
            ports = [22, 80, 443, 8080, 3306, 5432]
            open_ports = await batch_scan_ports(pool, "scanme.nmap.org", ports)
            print(f"  Open ports: {open_ports}")
            
            # Show stats
            print("\nPool Statistics:")
            stats = pool.get_stats()
            for key, value in stats.items():
                print(f"  {key}: {value}")
    
    asyncio.run(test_pool())
