"""Deterministic dirsearch 0.4.3-compatible word expansion.

The rules mirror the upstream ``Dictionary.generate`` behavior for the
supported subset: strip one leading slash, skip comments/invalid entries,
expand ``%EXT%``, force extensions only for extensionless non-directories,
and apply prefixes/suffixes without making a Cartesian product.
"""

from __future__ import annotations

import re
from collections.abc import Iterable


def _normalise_extensions(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        value = str(item).strip().lstrip(".")
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _clean_path(value: str) -> str:
    """Match upstream ``clean_path`` default: drop fragment and query."""

    return value.split("#", 1)[0].split("?", 1)[0]


def _lstrip_once(value: str, character: str) -> str:
    return value[1:] if value.startswith(character) else value


def _is_excluded(value: str, excluded: set[str]) -> bool:
    cleaned = _clean_path(value).lower()
    return any(cleaned.endswith(f".{extension}") for extension in excluded)


def word_variants(
    word: str,
    extensions: Iterable[str],
    force_extensions: Iterable[str],
    exclude_extensions: Iterable[str],
) -> list[str]:
    """Return variants for one wordlist entry.

    ``force_extensions`` may be empty or contain the extensions to append.
    A non-empty value is the project's equivalent of upstream ``-f`` plus
    the selected extension list.
    """

    value = _lstrip_once(word.strip(), "/")
    if not value or value.startswith("#"):
        return []

    extension_values = _normalise_extensions(extensions)
    force_values = _normalise_extensions(force_extensions)
    excluded = {extension.lower() for extension in _normalise_extensions(exclude_extensions)}
    if _is_excluded(value, excluded):
        return []

    variants: list[str] = []
    if "%ext%" in value.lower():
        # Upstream emits no literal %EXT% entry when no extension is selected.
        for extension in extension_values:
            variants.append(re.sub(r"%ext%", extension, value, flags=re.IGNORECASE))
    else:
        variants.append(value)
        if force_values and "." not in value and not value.endswith("/"):
            variants.append(value + "/")
            variants.extend(f"{value}.{extension}" for extension in force_values)

    result: list[str] = []
    seen: set[str] = set()
    for variant in variants:
        if variant and variant not in seen:
            seen.add(variant)
            result.append(variant)
    return result


def expand_words(
    words: list[str],
    extensions: list[str],
    prefixes: list[str],
    suffixes: list[str],
    force_extensions: list[str] | None = None,
    exclude_extensions: list[str] | None = None,
) -> list[str]:
    """Expand a wordlist using the upstream 0.4.3 ordering rules.

    Upstream replaces the base set with the altered set when prefixes or
    suffixes are present. It does not generate every prefix/suffix pair.
    Empty prefix/suffix values are filtered, as in upstream option parsing.
    """

    base: list[str] = []
    seen_base: set[str] = set()
    for word in words:
        for variant in word_variants(
            word,
            extensions,
            force_extensions or [],
            exclude_extensions or [],
        ):
            if variant not in seen_base:
                seen_base.add(variant)
                base.append(variant)

    prefix_values = [str(item).strip() for item in prefixes if str(item).strip()]
    suffix_values = [str(item).strip() for item in suffixes if str(item).strip()]
    altered: list[str] = []
    seen_altered: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen_altered:
            seen_altered.add(value)
            altered.append(value)

    for value in base:
        for prefix in prefix_values:
            if not value.startswith(("/", prefix)):
                add(prefix + value)
        for suffix in suffix_values:
            if not value.endswith(("/", suffix)) and "?" not in value and "#" not in value:
                add(value + suffix)

    return altered or base


__all__ = ["expand_words", "word_variants"]
