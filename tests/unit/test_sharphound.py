from unittest.mock import Mock
from bluehound.ingestion.sharphound import SharpHoundIngester

def test_recursive_sid_normalization():
    data = {"a":["s-1-5-21-1"]}
    from bluehound.ingestion.sharphound import _normalize_sid_recursive
    result = _normalize_sid_recursive(data)
    assert result["a"][0] == "S-1-5-21-1"


def test_relationship_type_validation():
    from bluehound.ingestion.sharphound import ALLOWED_REL_TYPES
    assert "GenericAll" in ALLOWED_REL_TYPES


def test_domain_from_domains_json():
    ing = SharpHoundIngester(Mock())
    dataset = {
        "data":[
            {"Properties":{"distinguishedname":"DC=corp,DC=local"}}
        ]
    }
    assert ing._extract_domain_from_domains(dataset) == "CORP.LOCAL"

def test_property_sanitization():
    ing = SharpHoundIngester(Mock())

    raw = {
        "samaccountname": "user1",
        "nested": {"bad": "value"},
        "list_bad": [{"x": 1}],
        "list_good": ["a", "b"],
    }

    clean = ing._sanitize_properties(raw)

    assert "nested" not in clean
    assert "list_bad" not in clean
    assert "list_good" in clean
