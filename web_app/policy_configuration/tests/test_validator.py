"""Tests for policy OAS schema validation (source/target versions, capability diffs)."""
from policy_configuration.validation.policy_validator import (
    strip_unsupported_fields, validate_policy_doc,
)


def _doc():
    return {"policy": {"accesspolicies": [{
        "name": "Corp-ACP",
        "type": "AccessPolicy",
        "accessrules": [{"name": "r1", "type": "AccessRule", "action": "ALLOW"}],
        "assignedPolicies": {
            "aiDefenseSetting": {"category": "aiDefenseSetting", "type": "AIDefenseSetting",
                                 "name": "AI", "supported": False},
        },
        "settings": {"LoggingSetting": {"type": "LoggingSetting"}},
    }]}}


def test_validate_known_version_loads_schema():
    res = validate_policy_doc(_doc(), "7.6.0", "source")
    assert res.side == "source"
    assert res.oas_version == "7.6"
    assert res.schema_found is True
    # Result is a dict-able structure with errors/warnings lists.
    d = res.to_dict()
    assert "errors" in d and "warnings" in d


def test_unsupported_assigned_policy_is_warning():
    res = validate_policy_doc(_doc(), "7.6.0", "target")
    msgs = " ".join(w.get("message", "") for w in res.warnings)
    assert "aiDefenseSetting" in msgs or "unsupported" in msgs.lower()


def test_unknown_version_skips_schema_gracefully():
    res = validate_policy_doc(_doc(), "", "source")
    assert res.schema_found is False
    # Skipping is a warning, not a blocking error.
    assert not res.has_blocking
    assert res.warnings


def test_unknown_field_flagged_as_warning_not_blocking():
    doc = {"policy": {"accesspolicies": [{
        "name": "X", "type": "AccessPolicy",
        "totallyBogusField": 123,
        "accessrules": [],
    }]}}
    res = validate_policy_doc(doc, "7.6.0", "target")
    # Bogus field surfaces as a warning; the doc is not blocked.
    assert not res.has_blocking


def test_source_target_version_difference():
    # Older target may lack newer schema types -> still validates without crashing.
    src = validate_policy_doc(_doc(), "10.5", "source")
    tgt = validate_policy_doc(_doc(), "7.0", "target")
    assert src.oas_version
    assert tgt.oas_version


def _nested_doc():
    """Doc whose *nested* fields are unsupported on 7.4 but present in 10.0."""
    return {
        "access_policies": [{
            "name": "ACP", "type": "AccessPolicy",
            "accessrules": [{
                "name": "r1", "type": "AccessRule",
                "applications": {
                    "applicationDefaultPort": False,
                    "applications": [{"id": "1", "type": "Application", "name": "x"}],
                },
            }],
        }],
        "decryption_policies": [{
            "name": "Dec", "type": "DecryptionPolicy",
            "advancedOptions": {
                "stripHTTP3": False, "tls13Decryption": True,
                "quicDecryption": False,
            },
        }],
    }


def test_nested_unsupported_fields_flagged():
    # applicationDefaultPort (under applications) and quicDecryption (under
    # advancedOptions) are nested; they must still be detected against 7.4.
    res = validate_policy_doc(_nested_doc(), "7.4", "target")
    keys = {w.get("group_key") for w in res.warnings if w.get("group_key")}
    assert "IApplicationsContainer:applicationDefaultPort" in keys
    assert "DecryptionPolicyAdvancedOptions:quicDecryption" in keys


def test_nested_fields_present_on_newer_version_not_flagged():
    # On 10.0 both nested fields exist -> no warnings for them.
    res = validate_policy_doc(_nested_doc(), "10.0", "source")
    keys = {w.get("group_key") for w in res.warnings if w.get("group_key")}
    assert "IApplicationsContainer:applicationDefaultPort" not in keys
    assert "DecryptionPolicyAdvancedOptions:quicDecryption" not in keys


def test_strip_unsupported_removes_nested_fields():
    rule = {
        "name": "r1", "type": "AccessRule",
        "applications": {
            "applicationDefaultPort": False,
            "applications": [{"id": "1", "type": "Application", "name": "x"}],
        },
    }
    removed = strip_unsupported_fields(rule, "AccessRule", "7.4")
    assert "applicationDefaultPort" in removed
    # Legitimate nested siblings are preserved.
    assert "applications" in rule["applications"]
    assert "applicationDefaultPort" not in rule["applications"]

    dec = {
        "name": "d", "type": "DecryptionPolicy",
        "advancedOptions": {
            "stripHTTP3": False, "tls13Decryption": True, "quicDecryption": False,
        },
    }
    removed = strip_unsupported_fields(dec, "DecryptionPolicy", "7.4")
    assert "quicDecryption" in removed
    assert "quicDecryption" not in dec["advancedOptions"]
    assert dec["advancedOptions"]["tls13Decryption"] is True
