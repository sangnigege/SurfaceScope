from __future__ import annotations

from surfacescope.cli import _int_csv
from surfacescope.components.dirsearch import expand_words, word_variants


def test_supported_wordlist_contract_matches_dirsearch_043_fixture() -> None:
    # Cases mirror lib/core/dictionary.py in dirsearch v0.4.3. The project
    # intentionally keeps this subset deterministic and shares one executor.
    assert word_variants("/admin", [], [], []) == ["admin"]
    assert word_variants("# comment", [], [], []) == []
    assert word_variants("", [], [], []) == []
    assert word_variants("api.%EXT%", ["json", "xml"], [], []) == ["api.json", "api.xml"]
    assert word_variants("api.%EXT%", [], [], []) == []
    assert word_variants("admin", ["php"], ["php"], []) == ["admin", "admin/", "admin.php"]
    assert word_variants("admin.php", ["php"], ["php"], []) == ["admin.php"]
    assert word_variants("admin/", ["php"], ["php"], []) == ["admin/"]
    assert word_variants("secret.php?x=1", [], [], ["php"]) == []
    assert expand_words(["a.%EXT%"], ["js"], ["api/"], [".bak"]) == ["api/a.js", "a.js.bak"]
    assert expand_words(["keep", "keep"], [], [], []) == ["keep"]


def test_cli_status_ranges_expand_for_043_compatibility() -> None:
    assert _int_csv("200-204,301,304") == [200, 201, 202, 203, 204, 301, 304]
    assert _int_csv("403,401") == [401, 403]
