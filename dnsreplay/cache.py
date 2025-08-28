"""Async TTL cache with per-key locks to prevent thundering herd."""

import asyncio
import logging
import time
from typing import Any, Dict, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CacheEntry:
    """Represents a cached entry with TTL and metadata."""
    
    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.created_at = time.time()
        self.ttl = ttl
        
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        return time.time() - self.created_at > self.ttl
        
    def age_seconds(self) -> float:
        """Get the age of the cache entry in seconds."""
        return time.time() - self.created_at


class AsyncTTLCache:
    """
    Async TTL cache with per-key locks to prevent thundering herd problems.
    
    Features:
    - TTL-based expiration
    - Per-key locks to prevent duplicate concurrent requests
    - Thread-safe operations
    - Automatic cleanup of expired entries
    """
    
    def __init__(self, default_ttl: float = 3600.0, cleanup_interval: float = 300.0):
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        self._cache: Dict[str, CacheEntry] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "evictions": 0
        }
        
    async def start_cleanup_task(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            
    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
                
    async def get(self, key: str) -> Optional[Any]:
        """
        Get a value from the cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value if exists and not expired, None otherwise
        """
        async with self._global_lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats["misses"] += 1
                return None
                
            if entry.is_expired():
                # Remove expired entry
                del self._cache[key]
                if key in self._locks:
                    del self._locks[key]
                self._stats["misses"] += 1
                self._stats["evictions"] += 1
                return None
                
            self._stats["hits"] += 1
            return entry.value
            
    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """
        Set a value in the cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds (uses default if None)
        """
        if ttl is None:
            ttl = self.default_ttl
            
        async with self._global_lock:
            self._cache[key] = CacheEntry(value, ttl)
            self._stats["sets"] += 1
            
    async def get_lock(self, key: str) -> asyncio.Lock:
        """
        Get a per-key lock to prevent thundering herd.
        
        Args:
            key: Cache key
            
        Returns:
            Asyncio lock for the given key
        """
        async with self._global_lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
            return self._locks[key]
            
    async def delete(self, key: str) -> bool:
        """
        Delete a key from the cache.
        
        Args:
            key: Cache key to delete
            
        Returns:
            True if key existed, False otherwise
        """
        async with self._global_lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._locks:
                    del self._locks[key]
                return True
            return False
            
    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._global_lock:
            self._cache.clear()
            self._locks.clear()
            logger.info("Cache cleared")
            
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self._stats,
            "total_requests": total_requests,
            "hit_rate_percent": round(hit_rate, 2),
            "cache_size": len(self._cache),
            "active_locks": len(self._locks)
        }
        
    async def _cleanup_loop(self) -> None:
        """Background task to clean up expired entries."""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                logger.info("Cache cleanup task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
                
    async def _cleanup_expired(self) -> None:
        """Remove expired entries from the cache."""
        async with self._global_lock:
            expired_keys = []
            
            for key, entry in self._cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
                    
            for key in expired_keys:
                del self._cache[key]
                if key in self._locks:
                    del self._locks[key]
                self._stats["evictions"] += 1
                
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
