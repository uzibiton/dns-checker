"""Test utilities and domain normalization."""

import pytest
from dnsreplay.utils import normalize_domain, classify_reputation, extract_query_source


class TestDomainNormalization:
    """Test domain normalization functionality."""
    
    def test_remove_trailing_dot(self):
        """Test removal of trailing dots."""
        assert normalize_domain("example.com.") == "example.com"
        assert normalize_domain("test.org..") == "test.org"
        
    def test_lowercase_conversion(self):
        """Test conversion to lowercase."""
        assert normalize_domain("EXAMPLE.COM") == "example.com"
        assert normalize_domain("Test.ORG") == "test.org"
        
    def test_combined_normalization(self):
        """Test combined normalization."""
        assert normalize_domain("EXAMPLE.COM.") == "example.com"
        assert normalize_domain("Test.ORG.") == "test.org"
        
    def test_empty_domain(self):
        """Test empty domain handling."""
        assert normalize_domain("") == ""
        assert normalize_domain(".") == ""
        
    def test_idn_domains(self):
        """Test international domain names."""
        # This test might need adjustment based on actual IDN handling
        result = normalize_domain("münchen.de")
        assert result in ("münchen.de", "xn--mnchen-3ya.de")


class TestReputation:
    """Test reputation classification."""
    
    def test_trusted_classification(self):
        """Test trusted score classification."""
        assert classify_reputation(61) == "Trusted"
        assert classify_reputation(100) == "Trusted"
        assert classify_reputation(85) == "Trusted"
        
    def test_untrusted_classification(self):
        """Test untrusted score classification."""
        assert classify_reputation(0) == "Untrusted"
        assert classify_reputation(60) == "Untrusted"
        assert classify_reputation(30) == "Untrusted"
        
    def test_boundary_values(self):
        """Test boundary values."""
        assert classify_reputation(60) == "Untrusted"
        assert classify_reputation(61) == "Trusted"


class TestQuerySource:
    """Test query source extraction."""
    
    def test_basic_extraction(self):
        """Test basic query source extraction."""
        packet_info = {
            "src_ip": "192.168.1.1",
            "src_port": "12345",
            "dst_ip": "8.8.8.8",
            "dst_port": "53",
            "frame_no": "100"
        }
        
        result = extract_query_source(packet_info)
        expected = "pcap:frame_100:192.168.1.1:12345->8.8.8.8:53"
        assert result == expected
        
    def test_missing_fields(self):
        """Test extraction with missing fields."""
        packet_info = {"frame_no": "200"}
        
        result = extract_query_source(packet_info)
        expected = "pcap:frame_200:unknown:unknown->unknown:unknown"
        assert result == expected
