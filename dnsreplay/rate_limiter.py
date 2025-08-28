"""Rate limiting utilities for controlling API request frequency."""

import asyncio
import time
from typing import Optional


class TokenBucketRateLimiter:
    """
    Token bucket rate limiter for async operations.
    
    Allows bursts up to the bucket capacity while maintaining
    an average rate over time.
    """
    
    def __init__(self, rate: float, capacity: Optional[int] = None):
        """
        Initialize the rate limiter.
        
        Args:
            rate: Tokens per second (requests per second)
            capacity: Maximum burst capacity (defaults to rate * 2)
        """
        self.rate = rate
        self.capacity = capacity or max(int(rate * 2), 1)
        self.tokens = float(self.capacity)
        self.last_update = time.time()
        self._lock = asyncio.Lock()
        
    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens from the bucket, waiting if necessary.
        
        Args:
            tokens: Number of tokens to acquire (default: 1)
        """
        async with self._lock:
            await self._wait_for_tokens(tokens)
            self.tokens -= tokens
            
    async def _wait_for_tokens(self, tokens: int) -> None:
        """Wait until sufficient tokens are available."""
        while True:
            self._refill_bucket()
            
            if self.tokens >= tokens:
                break
                
            # Calculate how long to wait for enough tokens
            tokens_needed = tokens - self.tokens
            wait_time = tokens_needed / self.rate
            
            # Sleep for the calculated time
            await asyncio.sleep(wait_time)
            
    def _refill_bucket(self) -> None:
        """Refill the token bucket based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        
        # Add tokens based on elapsed time
        tokens_to_add = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        
        self.last_update = now
        
    def get_tokens(self) -> float:
        """Get current number of tokens in the bucket."""
        self._refill_bucket()
        return self.tokens


class SemaphoreRateLimiter:
    """
    Semaphore-based rate limiter for controlling concurrency.
    
    Simpler than token bucket but doesn't provide the same
    precise rate control. Good for limiting concurrent requests.
    """
    
    def __init__(self, max_concurrent: int):
        """
        Initialize the semaphore rate limiter.
        
        Args:
            max_concurrent: Maximum concurrent operations
        """
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
    async def acquire(self) -> None:
        """Acquire the semaphore."""
        await self._semaphore.acquire()
        
    def release(self) -> None:
        """Release the semaphore."""
        self._semaphore.release()
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.acquire()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        self.release()
        
    def get_available(self) -> int:
        """Get number of available permits."""
        return self._semaphore._value


class CombinedRateLimiter:
    """
    Combines token bucket rate limiting with semaphore concurrency control.
    
    Provides both rate limiting (requests per second) and concurrency
    limiting (maximum simultaneous requests).
    """
    
    def __init__(self, rate: float, max_concurrent: int):
        """
        Initialize the combined rate limiter.
        
        Args:
            rate: Requests per second
            max_concurrent: Maximum concurrent requests
        """
        self.rate_limiter = TokenBucketRateLimiter(rate)
        self.concurrency_limiter = SemaphoreRateLimiter(max_concurrent)
        
    async def acquire(self) -> None:
        """Acquire both rate and concurrency limits."""
        # First acquire rate limit
        await self.rate_limiter.acquire()
        # Then acquire concurrency limit
        await self.concurrency_limiter.acquire()
        
    def release(self) -> None:
        """Release concurrency limit."""
        self.concurrency_limiter.release()
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.acquire()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        self.release()
        
    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        return {
            "tokens_available": self.rate_limiter.get_tokens(),
            "tokens_capacity": self.rate_limiter.capacity,
            "rate_per_second": self.rate_limiter.rate,
            "concurrent_available": self.concurrency_limiter.get_available(),
            "max_concurrent": self.concurrency_limiter.max_concurrent
        }
