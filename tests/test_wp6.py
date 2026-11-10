"""WP6: process-data flattening and the no-identity feature set."""
from federated_ids.gridstrat.analysis import VOLUME
from federated_ids.gridstrat.wp6_no_arp import NOID, _flatten


def test_flatten_numeric_leaves_only():
    out: dict = {}
    _flatten({"control": {"on_off": True, "mode": "auto"}, "monitor": {"power": 5, "temp": {"a": 1.5}}}, "pv", out)
    assert out == {"pv.control.on_off": 1.0, "pv.monitor.power": 5.0, "pv.monitor.temp.a": 1.5}


def test_noid_drops_binding_and_host_counts():
    assert "n_src_mac" not in NOID and "n_src_ip" not in NOID
    assert "n_arp" not in NOID and "n_ip_multi_mac" not in NOID
    assert set(NOID) == set(VOLUME) - {"n_src_mac", "n_src_ip"}
