"""Static JavaScript and URL extraction shared by discovery components."""

from .extract import base_href, extract_script_urls, extract_urls, normalise_extracted_url

__all__ = [
    "base_href",
    "extract_script_urls",
    "extract_urls",
    "normalise_extracted_url",
]
