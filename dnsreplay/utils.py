"""Domain normalization utilities."""

import idna
from typing import Optional


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name for consistent caching and lookup.
    
    Args:
        domain: Raw domain name from DNS query
        
    Returns:
        Normalized domain name (lowercase, no trailing dot, punycode)
        
    Examples:
        >>> normalize_domain("EXAMPLE.COM.")
        'example.com'
        >>> normalize_domain("münchen.de")
        'xn--mnchen-3ya.de'
    """
    if not domain:
        return ""
    
    # Remove trailing dot
    domain = domain.rstrip(".")
    
    # Convert to lowercase
    domain = domain.lower()
    
    # Handle internationalized domain names (IDN)
    try:
        # Convert to ASCII (punycode) if needed
        domain = idna.encode(domain, uts46=True).decode('ascii')
    except (idna.core.IDNAError, UnicodeError):
        # If IDN encoding fails, use the domain as-is
        pass
    
    return domain


def classify_reputation(score: int) -> str:
    """
    Classify reputation score into Trusted/Untrusted.
    
    Args:
        score: Reputation score (0-100)
        
    Returns:
        "Trusted" for scores 61-100, "Untrusted" for 0-60
    """
    return "Trusted" if score >= 61 else "Untrusted"


def extract_query_source(packet_info: dict) -> str:
    """
    Extract query source information from packet metadata.
    
    Args:
        packet_info: Dictionary with packet metadata
        
    Returns:
        Formatted query source string
    """
    src_ip = packet_info.get("src_ip", "unknown")
    src_port = packet_info.get("src_port", "unknown")
    dst_ip = packet_info.get("dst_ip", "unknown") 
    dst_port = packet_info.get("dst_port", "unknown")
    frame_no = packet_info.get("frame_no", "unknown")
    
    return f"pcap:frame_{frame_no}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
