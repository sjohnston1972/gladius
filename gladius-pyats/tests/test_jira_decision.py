"""Scheduled-diff Jira auto-ticket filter (#121)."""
import pytest

DEFAULT = "Network Change Detected — nightly"


@pytest.mark.parametrize("jira_auto,analysis,expected", [
    # analysis missing / unparsable: only 'all' may ticket
    ("all",         "",                              (True,  "P3", DEFAULT)),
    ("medium_plus", "",                              (False, None, DEFAULT)),
    ("high_only",   "",                              (False, None, DEFAULT)),
    ("high_only",   "model rambled, no severity",    (False, None, DEFAULT)),
    # severity present
    ("all",         "SEVERITY: LOW\nSUMMARY: x",     (True,  "P4", "x")),
    ("medium_plus", "SEVERITY: LOW",                 (False, "P4", DEFAULT)),
    ("medium_plus", "severity: medium",              (True,  "P3", DEFAULT)),
    ("medium_plus", "SEVERITY: HIGH\nSUMMARY: BGP down", (True, "P2", "BGP down")),
    ("high_only",   "SEVERITY: MEDIUM",              (False, "P3", DEFAULT)),
    ("high_only",   "SEVERITY: HIGH",                (True,  "P2", DEFAULT)),
])
def test_jira_ticket_decision(app, jira_auto, analysis, expected):
    assert app._jira_ticket_decision(jira_auto, analysis, DEFAULT) == expected
