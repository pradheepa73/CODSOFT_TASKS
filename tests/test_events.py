from aegis.core.events import Event, EventBus


def test_event_bus_roundtrip(tmp_path):
    db = tmp_path / "t.db"
    bus = EventBus(db)
    bus.emit(Event(module="test", severity="high", title="hello"))
    rows = bus.recent(limit=10)
    assert len(rows) == 1
    assert rows[0]["severity"] == "high"


def test_min_severity_filter(tmp_path):
    bus = EventBus(tmp_path / "t.db")
    bus.emit(Event(module="t", severity="info", title="a"))
    bus.emit(Event(module="t", severity="critical", title="b"))
    rows = bus.recent(limit=10, min_severity="high")
    assert len(rows) == 1 and rows[0]["severity"] == "critical"