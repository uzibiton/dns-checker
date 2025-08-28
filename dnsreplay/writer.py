"""Writers for outputting results to CSV and JSON Lines formats."""

import asyncio
import csv
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

from .reputation import ReputationResult

logger = logging.getLogger(__name__)


class CSVWriter:
    """Async CSV writer for reputation results."""
    
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self._file = None
        self._writer = None
        self._headers_written = False
        
        # CSV field names
        self.fieldnames = [
            "domain",
            "reputation_score", 
            "classification",
            "categories",
            "query_source",
            "response_time_ms",
            "timestamp_utc",
            "cached",
            "attempts",
            "http_status",
            "status",
            "error_message"
        ]
        
    async def __aenter__(self):
        """Async context manager entry."""
        self._file = await aiofiles.open(self.file_path, mode='w', newline='', encoding='utf-8')
        self._writer = csv.DictWriter(self._file, fieldnames=self.fieldnames)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._file:
            await self._file.close()
            
    async def write_result(self, result: ReputationResult, query_source: str = "") -> None:
        """
        Write a reputation result to CSV.
        
        Args:
            result: ReputationResult to write
            query_source: Query source information
        """
        if not self._headers_written:
            await self._file.write(','.join(self.fieldnames) + '\n')
            self._headers_written = True
            
        # Convert result to CSV row
        row_data = result.to_dict()
        row_data["query_source"] = query_source
        row_data["categories"] = json.dumps(row_data["categories"])  # Serialize list as JSON
        
        # Write row
        csv_line = ','.join([
            self._escape_csv_value(str(row_data.get(field, "")))
            for field in self.fieldnames
        ])
        await self._file.write(csv_line + '\n')
        await self._file.flush()
        
    def _escape_csv_value(self, value: str) -> str:
        """Escape CSV value if it contains special characters."""
        if ',' in value or '"' in value or '\n' in value:
            # Escape quotes and wrap in quotes
            escaped = value.replace('"', '""')
            return f'"{escaped}"'
        return value


class JSONLWriter:
    """Async JSON Lines writer for reputation results."""
    
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self._file = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        self._file = await aiofiles.open(self.file_path, mode='w', encoding='utf-8')
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._file:
            await self._file.close()
            
    async def write_result(self, result: ReputationResult, query_source: str = "") -> None:
        """
        Write a reputation result as JSON Line.
        
        Args:
            result: ReputationResult to write
            query_source: Query source information
        """
        # Convert result to dict and add query source
        data = result.to_dict()
        data["query_source"] = query_source
        
        # Write JSON line
        json_line = json.dumps(data, ensure_ascii=False)
        await self._file.write(json_line + '\n')
        await self._file.flush()


class SamplesWriter:
    """Writer for detailed API call samples (debug output)."""
    
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self._file = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        self._file = await aiofiles.open(self.file_path, mode='w', encoding='utf-8')
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._file:
            await self._file.close()
            
    async def write_sample(
        self, 
        domain: str,
        attempt: int,
        response_time_ms: int,
        http_status: Optional[int],
        success: bool,
        error: Optional[str] = None,
        cached: bool = False
    ) -> None:
        """
        Write a detailed API call sample.
        
        Args:
            domain: Domain that was queried
            attempt: Attempt number (1-based)
            response_time_ms: Response time in milliseconds
            http_status: HTTP status code
            success: Whether the call was successful
            error: Error message if any
            cached: Whether this was a cache hit
        """
        sample = {
            "timestamp": asyncio.get_event_loop().time(),
            "domain": domain,
            "attempt": attempt,
            "response_time_ms": response_time_ms,
            "http_status": http_status,
            "success": success,
            "error": error,
            "cached": cached
        }
        
        json_line = json.dumps(sample, ensure_ascii=False)
        await self._file.write(json_line + '\n')
        await self._file.flush()


class ResultsManager:
    """
    Manages multiple result writers and provides unified interface.
    """
    
    def __init__(
        self,
        csv_path: Optional[Path] = None,
        jsonl_path: Optional[Path] = None,
        samples_path: Optional[Path] = None
    ):
        self.csv_path = csv_path
        self.jsonl_path = jsonl_path
        self.samples_path = samples_path
        
        self._csv_writer: Optional[CSVWriter] = None
        self._jsonl_writer: Optional[JSONLWriter] = None
        self._samples_writer: Optional[SamplesWriter] = None
        
        # Track written results to avoid duplicates
        self._written_domains: set = set()
        
    async def __aenter__(self):
        """Async context manager entry."""
        if self.csv_path:
            self._csv_writer = CSVWriter(self.csv_path)
            await self._csv_writer.__aenter__()
            
        if self.jsonl_path:
            self._jsonl_writer = JSONLWriter(self.jsonl_path)
            await self._jsonl_writer.__aenter__()
            
        if self.samples_path:
            self._samples_writer = SamplesWriter(self.samples_path)
            await self._samples_writer.__aenter__()
            
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._csv_writer:
            await self._csv_writer.__aexit__(exc_type, exc_val, exc_tb)
            
        if self._jsonl_writer:
            await self._jsonl_writer.__aexit__(exc_type, exc_val, exc_tb)
            
        if self._samples_writer:
            await self._samples_writer.__aexit__(exc_type, exc_val, exc_tb)
            
    async def write_result(self, result: ReputationResult, query_source: str = "") -> None:
        """
        Write a reputation result to all configured writers.
        
        Only writes each unique domain once to main results.
        
        Args:
            result: ReputationResult to write
            query_source: Query source information
        """
        # Only write to main results if this domain hasn't been written yet
        if result.domain not in self._written_domains:
            if self._csv_writer:
                await self._csv_writer.write_result(result, query_source)
                
            if self._jsonl_writer:
                await self._jsonl_writer.write_result(result, query_source)
                
            self._written_domains.add(result.domain)
            logger.debug(f"Wrote result for domain: {result.domain}")
            
    async def write_sample(
        self,
        domain: str,
        attempt: int,
        response_time_ms: int,
        http_status: Optional[int],
        success: bool,
        error: Optional[str] = None,
        cached: bool = False
    ) -> None:
        """Write a detailed API call sample."""
        if self._samples_writer:
            await self._samples_writer.write_sample(
                domain, attempt, response_time_ms, http_status, 
                success, error, cached
            )
            
    def get_written_count(self) -> int:
        """Get the number of unique domains written."""
        return len(self._written_domains)
