"""Protocol-state walks and diffing: failed walks, hold-down, ifOperStatus mapping."""
import pytest

import app


class Val:
    """Stand-in for a pysnmp value."""
    def __init__(self, v):
        self.v = v

    def prettyPrint(self):
        return str(self.v)


class EndOfMibView(Val):
    pass


class Null(Val):
    pass


def ok(*var_binds):
    return (None, 0, 0, list(var_binds))


BGP = app._BGP_PEER_STATE


# ── _collect_walk ─────────────────────────────────────────────────────────────

def test_collect_walk_success():
    rows = app._collect_walk(BGP, [ok((f"{BGP}.10.0.0.1", Val(6))), ok((f"{BGP}.10.0.0.2", Val(1)))], 50)
    assert [(o, v.prettyPrint()) for o, v in rows] == [(f"{BGP}.10.0.0.1", "6"), (f"{BGP}.10.0.0.2", "1")]


@pytest.mark.parametrize("failure", [
    ("requestTimedOut", 0, 0, []),          # errorIndication
    (None, 5, 1, []),                        # errorStatus genErr
])
def test_collect_walk_error_is_none_not_empty(failure):
    assert app._collect_walk(BGP, [ok((f"{BGP}.10.0.0.1", Val(6))), failure], 50) is None
    assert app._collect_walk(BGP, [failure], 50) is None


def test_collect_walk_empty_table_is_empty_list():
    assert app._collect_walk(BGP, [], 50) == []


def test_collect_walk_skips_out_of_scope_and_padding_values():
    rows = app._collect_walk(BGP, [
        ok((f"{BGP}.10.0.0.1", Val(6))),
        ok((f"{BGP}.10.0.0.1", EndOfMibView(""))),   # GETBULK end padding
        ok((f"{BGP}.10.0.0.1", Null(""))),           # SNMPv1 end-of-walk
        ok(("1.3.6.1.2.1.15.3.1.3.10.0.0.1", Val(9))),  # next column
    ], 50)
    assert [o for o, _ in rows] == [f"{BGP}.10.0.0.1"]
    assert rows[0][1].prettyPrint() == "6"


def test_collect_walk_respects_max_rows():
    resp = [ok((f"{BGP}.10.0.0.{i}", Val(6))) for i in range(10)]
    assert len(app._collect_walk(BGP, resp, 3)) == 3


def test_build_interfaces():
    d, a, o = app._IF_DESCR, app._IF_ADMIN, app._IF_OPER
    ifs = app._build_interfaces(
        [(f"{d}.1", Val("Gi0/0")), (f"{d}.2", Val("Gi0/1"))],
        [(f"{a}.1", Val(1)), (f"{a}.2", Val(2))],
        [(f"{o}.1", Val(7)), (f"{o}.2", Val(2))],
    )
    assert ifs == {"Gi0/0": {"oper": "7", "admin": "1", "idx": "1"},
                   "Gi0/1": {"oper": "2", "admin": "2", "idx": "2"}}


# ── ifOperStatus mapping ──────────────────────────────────────────────────────

@pytest.mark.parametrize("oper, admin, expected", [
    ("1", "1", "up"),
    ("2", "1", "down"),
    ("5", "1", "down"),     # dormant
    ("6", "1", "down"),     # notPresent
    ("7", "1", "down"),     # lowerLayerDown
    ("3", "1", "other"),    # testing
    ("4", "1", "other"),    # unknown
    ("2", "2", "other"),    # admin shut — expected to be down
    ("7", "2", "other"),
])
def test_iface_health(oper, admin, expected):
    assert app._iface_health({"oper": oper, "admin": admin}) == expected


def test_iface_health_gone():
    assert app._iface_health(None) == "gone"


# ── _diff_protocol_state ──────────────────────────────────────────────────────

def ifs(**kw):
    """ifs(Gi0_0="1") → interfaces table; value "oper" or "oper/admin"."""
    out = {}
    for name, v in kw.items():
        oper, _, admin = v.partition("/")
        out[name.replace("_", "/")] = {"oper": oper, "admin": admin or "1", "idx": "1"}
    return out


def state(interfaces=None, bgp=None, ospf=None):
    return {"interfaces": interfaces, "bgp": bgp, "ospf": ospf}


def run(old, observations, hold=2):
    """Feed successive observations; return (final confirmed state, events per poll)."""
    pending, per_poll = {}, []
    confirmed = old
    for obs in observations:
        confirmed, specs = app._diff_protocol_state(confirmed, obs, pending, hold)
        per_poll.append([(s[0], s[1], s[2]) for s in specs])
    return confirmed, per_poll


def test_first_poll_is_baseline():
    confirmed, polls = run(None, [state(ifs(Gi0_0="2"), {"10.0.0.1": "1"}, {"10.0.0.2": "2"})])
    assert polls == [[]]
    assert confirmed["bgp"] == {"10.0.0.1": "1"}


@pytest.mark.parametrize("table, up_state, down_events", [
    ("bgp",  {"10.0.0.1": "6"}, [("bgp_down", "critical", "BGP peer 10.0.0.1 disappeared (was established)")]),
    ("ospf", {"10.0.0.2": "8"}, [("ospf_down", "critical", "OSPF neighbor 10.0.0.2 disappeared (was full)")]),
])
def test_failed_walk_vs_empty_table(table, up_state, down_events):
    base = state(ifs(), {}, {})
    base[table] = dict(up_state)
    failed = state(ifs(), {}, {})
    failed[table] = None
    # Failed walks: no events, confirmed state carried over, forever
    confirmed, polls = run(base, [failed] * 5)
    assert polls == [[]] * 5
    assert confirmed[table] == up_state
    # Successful empty walks: a real disappearance, reported after the hold-down
    empty = state(ifs(), {}, {})
    confirmed, polls = run(base, [empty, empty])
    assert polls == [[], down_events]
    assert confirmed[table] == {}


def test_failed_walk_does_not_reset_hold_down():
    base = state(ifs(), {"10.0.0.1": "6"}, {})
    down = state(ifs(), {"10.0.0.1": "1"}, {})
    _, polls = run(base, [down, state(ifs(), None, {}), down])
    assert polls[0] == [] and polls[1] == []
    assert polls[2] == [("bgp_down", "critical", "BGP peer 10.0.0.1 → idle (was established)")]


@pytest.mark.parametrize("hold, observations, expected", [
    # single down poll then recovery → nothing at all
    (2, ["2", "1"], [[], []]),
    # down on two consecutive polls → one critical event, then recovery
    (2, ["2", "2", "2", "1"],
        [[], [("interface_down", "critical", "Gi0/0 went DOWN")], [], [("interface_up", "info", "Gi0/0 came UP")]]),
    # hold=1 → immediate
    (1, ["2", "1"], [[("interface_down", "critical", "Gi0/0 went DOWN")], [("interface_up", "info", "Gi0/0 came UP")]]),
    # lowerLayerDown counts as down and its recovery is reported
    (2, ["7", "7", "1"],
        [[], [("interface_down", "critical", "Gi0/0 went DOWN (lowerLayerDown)")], [("interface_up", "info", "Gi0/0 came UP")]]),
    # dormant / notPresent count as down; the reported state is the latest one
    (2, ["5", "6"], [[], [("interface_down", "critical", "Gi0/0 went DOWN (notPresent)")]]),
    # flapping every poll never confirms
    (2, ["2", "1", "2", "1", "2", "1"], [[]] * 6),
    # testing/unknown are not down
    (2, ["3", "3", "4", "4"], [[]] * 4),
    # admin shutdown is not an alert
    (2, ["2/2", "2/2"], [[], []]),
])
def test_interface_hold_down(hold, observations, expected):
    base = state(ifs(Gi0_0="1"), {}, {})
    _, polls = run(base, [state(ifs(Gi0_0=o), {}, {}) for o in observations], hold)
    assert polls == expected


def test_admin_down_to_up_is_recovery():
    base = state(ifs(Gi0_0="2/2"), {}, {})
    _, polls = run(base, [state(ifs(Gi0_0="1/1"), {}, {})])
    assert polls == [[("interface_up", "info", "Gi0/0 came UP")]]


def test_interface_disappearing_needs_two_misses():
    base = state(ifs(Gi0_0="1", Gi0_1="1"), {}, {})
    _, polls = run(base, [state(ifs(Gi0_1="1"), {}, {})] * 3)
    assert polls == [[], [("interface_down", "warning", "Gi0/0 no longer present")], []]


def test_virtual_interface_disappearing_is_ignored():
    base = state(ifs(Loopback0="1", Vlan10="1"), {}, {})
    confirmed, polls = run(base, [state(ifs(), {}, {})] * 2)
    assert polls == [[], []]
    assert confirmed["interfaces"] == {}


def test_new_interface_appearing_down_is_held_down():
    base = state(ifs(Gi0_0="1"), {}, {})
    obs = state(ifs(Gi0_0="1", Tunnel5="2"), {}, {})
    _, polls = run(base, [obs, obs])
    assert polls == [[], [("interface_down", "critical", "Tunnel5 went DOWN")]]


def test_pending_down_keeps_last_confirmed_value():
    base = state(ifs(Gi0_0="1"), {"10.0.0.1": "6"}, {})
    confirmed, _ = run(base, [state(ifs(Gi0_0="2"), {"10.0.0.1": "1"}, {})])
    assert confirmed["interfaces"]["Gi0/0"]["oper"] == "1"
    assert confirmed["bgp"] == {"10.0.0.1": "6"}


@pytest.mark.parametrize("table, key, up, transient, expected_up", [
    ("bgp",  "10.0.0.1", "6", ["1", "3", "2", "3"], "BGP peer 10.0.0.1 → established (was active)"),
    ("ospf", "10.0.0.2", "8", ["2", "3", "4", "5"], "OSPF neighbor 10.0.0.2 → full (was exchangestart)"),
])
def test_peer_fsm_noise_is_suppressed(table, key, up, transient, expected_up):
    base = state(ifs(), {}, {})
    base[table] = {key: transient[0]}
    obs = []
    for t in transient[1:] + [up]:
        o = state(ifs(), {}, {})
        o[table] = {key: t}
        obs.append(o)
    _, polls = run(base, obs)
    assert polls[:-1] == [[]] * (len(obs) - 1)
    assert [e[2] for e in polls[-1]] == [expected_up]


def test_new_peer_established_is_info():
    base = state(ifs(), {}, {})
    _, polls = run(base, [state(ifs(), {"10.0.0.9": "6"}, {"10.0.0.8": "8"})])
    assert polls == [[("bgp_up", "info", "BGP peer 10.0.0.9 newly established"),
                      ("ospf_up", "info", "OSPF neighbor 10.0.0.8 newly full")]]


def test_ospf_down_reports_state():
    base = state(ifs(), {}, {"10.0.0.2": "8"})
    _, polls = run(base, [state(ifs(), {}, {"10.0.0.2": "1"})] * 2)
    assert polls[1] == [("ospf_down", "critical", "OSPF neighbor 10.0.0.2 → down (was full)")]


def test_baseline_for_table_that_previously_failed():
    # Interfaces walked fine, BGP never walked successfully before
    base = state(ifs(Gi0_0="1"), None, None)
    confirmed, polls = run(base, [state(ifs(Gi0_0="1"), {"10.0.0.1": "1"}, {})])
    assert polls == [[]]
    assert confirmed["bgp"] == {"10.0.0.1": "1"}


def test_detect_events_emits_via_add_event(monkeypatch):
    emitted = []
    monkeypatch.setattr(app, "_add_event", lambda dev, *spec: emitted.append(spec) or {"type": spec[0]})
    monkeypatch.setattr(app, "_hold_counts", {})
    dev = {"id": "d1", "host": "10.0.0.1"}
    old = state(ifs(Gi0_0="1"), {}, {})
    new = state(ifs(Gi0_0="2"), {}, {})
    confirmed, events = app._detect_events(dev, old, new)
    assert events == [] and app._hold_counts["d1"] == {"interfaces|Gi0/0": 1}
    confirmed, events = app._detect_events(dev, confirmed, new)
    assert [e["type"] for e in events] == ["interface_down"]
    assert app._hold_counts["d1"] == {}
