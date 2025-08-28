"""Async reputation client with retries, timeouts, and proper error handling."""

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Tuple

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential_jitter,
    retry_if_exception_type,
    retry_if_result
)

from .utils import classify_reputation

logger = logging.getLogger(__name__)


class ReputationResult:
    """Represents the result of a reputation lookup."""
    
    def __init__(
        self,
        domain: str,
        reputation_score: Optional[int] = None,
        classification: Optional[str] = None,
        categories: Optional[list] = None,
        response_time_ms: int = 0,
        http_status: Optional[int] = None,
        status: str = "failed",
        error_message: Optional[str] = None,
        attempts: int = 1,
        cached: bool = False
    ):
        self.domain = domain
        self.reputation_score = reputation_score
        self.classification = classification
        self.categories = categories or []
        self.response_time_ms = response_time_ms
        self.http_status = http_status
        self.status = status
        self.error_message = error_message
        self.attempts = attempts
        self.cached = cached
        self.timestamp_utc = time.time()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "domain": self.domain,
            "reputation_score": self.reputation_score,
            "classification": self.classification,
            "categories": self.categories,
            "response_time_ms": self.response_time_ms,
            "http_status": self.http_status,
            "status": self.status,
            "error_message": self.error_message,
            "attempts": self.attempts,
            "cached": self.cached,
            "timestamp_utc": self.timestamp_utc
        }


class ReputationClient:
    """
    Async HTTP client for domain reputation lookups.
    
    Features:
    - Configurable timeouts and retries
    - Exponential backoff with jitter
    - Proper error classification
    - Request/response logging
    """
    
    def __init__(
        self,
        base_url: str = "https://microcks.gin.dev.securingsam.io/rest/Reputation+API/1.0.0/domain/ranking",
        auth_token: str = "I_am_under_stress_when_I_test",
        timeout: float = 10.0,
        max_retries: int = 3
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.timeout = timeout
        self.max_retries = max_retries
        
        # HTTP client configuration
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={
                "Authorization": f"Token {auth_token}",
                "Accept": "application/json",
                "User-Agent": "dnsreplay/1.0.0"
            },
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
        )
        
    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()
        
    async def lookup_reputation(self, domain: str) -> ReputationResult:
        """
        Look up domain reputation with retries and error handling.
        
        Args:
            domain: Normalized domain name
            
        Returns:
            ReputationResult with lookup results
        """
        start_time = time.time()
        attempt = 0
        last_exception = None
        
        @retry(
            stop=stop_after_attempt(self.max_retries),
            wait=wait_exponential_jitter(initial=1, max=10, jitter=2),
            retry=(
                retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError, httpx.ReadError)) |
                retry_if_result(lambda result: result and result[1] and result[1] >= 500)
            ),
            reraise=True
        )
        async def _make_request() -> Tuple[httpx.Response, int]:
            nonlocal attempt
            attempt += 1
            
            try:
                url = f"{self.base_url}/{domain}"
                logger.debug(f"Requesting reputation for {domain} (attempt {attempt})")
                
                response = await self.client.get(url)
                return response, response.status_code
                
            except Exception as e:
                logger.warning(f"Request failed for {domain} (attempt {attempt}): {e}")
                raise
                
        try:
            response, status_code = await _make_request()
            response_time_ms = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                return self._parse_success_response(
                    domain, response, response_time_ms, attempt
                )
            else:
                return self._create_error_result(
                    domain,
                    response_time_ms,
                    attempt,
                    http_status=response.status_code,
                    error_message=f"HTTP {response.status_code}: {response.text[:200]}"
                )
                
        except Exception as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"All attempts failed for {domain}: {e}")
            
            return self._create_error_result(
                domain,
                response_time_ms,
                attempt,
                error_message=str(e)
            )
            
    def _parse_success_response(
        self, 
        domain: str, 
        response: httpx.Response, 
        response_time_ms: int,
        attempts: int
    ) -> ReputationResult:
        """Parse a successful API response."""
        try:
            data = response.json()
            
            reputation_score = data.get("reputation", 0)
            if not isinstance(reputation_score, int):
                reputation_score = int(reputation_score) if reputation_score else 0
                
            classification = classify_reputation(reputation_score)
            categories = data.get("categories", [])
            
            if not isinstance(categories, list):
                categories = [str(categories)] if categories else []
                
            return ReputationResult(
                domain=domain,
                reputation_score=reputation_score,
                classification=classification,
                categories=categories,
                response_time_ms=response_time_ms,
                http_status=response.status_code,
                status="success",
                attempts=attempts
            )
            
        except Exception as e:
            logger.error(f"Failed to parse response for {domain}: {e}")
            return self._create_error_result(
                domain,
                response_time_ms,
                attempts,
                http_status=response.status_code,
                error_message=f"Parse error: {e}"
            )
            
    def _create_error_result(
        self,
        domain: str,
        response_time_ms: int,
        attempts: int,
        http_status: Optional[int] = None,
        error_message: Optional[str] = None
    ) -> ReputationResult:
        """Create a ReputationResult for errors."""
        # Determine status based on error type
        status = "failed"
        if "timeout" in (error_message or "").lower():
            status = "timeout"
            
        return ReputationResult(
            domain=domain,
            response_time_ms=response_time_ms,
            http_status=http_status,
            status=status,
            error_message=error_message,
            attempts=attempts
        )
