"""Test cache functionality."""

import asyncio
import time
from dnsreplay.cache import AsyncTTLCache


class TestAsyncTTLCache:
    """Test async TTL cache functionality."""
    
    async def test_basic_get_set(self):
        """Test basic get/set operations."""
        cache = AsyncTTLCache(default_ttl=60.0)
        
        # Test cache miss
        result = await cache.get("test-key")
        assert result is None
        
        # Test cache set and hit
        await cache.set("test-key", "test-value")
        result = await cache.get("test-key")
        assert result == "test-value"
        
    async def test_ttl_expiration(self):
        """Test TTL expiration."""
        cache = AsyncTTLCache(default_ttl=0.1)  # 100ms TTL
        
        await cache.set("expire-key", "expire-value")
        
        # Should be available immediately
        result = await cache.get("expire-key")
        assert result == "expire-value"
        
        # Wait for expiration
        await asyncio.sleep(0.2)
        
        # Should be expired
        result = await cache.get("expire-key")
        assert result is None
        
    async def test_per_key_locks(self):
        """Test per-key locks."""
        cache = AsyncTTLCache(default_ttl=60.0)
        
        # Get locks for same key should be the same object
        lock1 = await cache.get_lock("same-key")
        lock2 = await cache.get_lock("same-key")
        assert lock1 is lock2
        
        # Get locks for different keys should be different objects
        lock3 = await cache.get_lock("different-key")
        assert lock1 is not lock3
        
    async def test_cache_stats(self):
        """Test cache statistics."""
        cache = AsyncTTLCache(default_ttl=60.0)
        
        # Initial stats
        stats = cache.get_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["sets"] == 0
        
        # After miss
        await cache.get("missing-key")
        stats = cache.get_stats()
        assert stats["misses"] == 1
        
        # After set and hit
        await cache.set("hit-key", "hit-value")
        await cache.get("hit-key")
        stats = cache.get_stats()
        assert stats["sets"] == 1
        assert stats["hits"] == 1
