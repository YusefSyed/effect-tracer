"""W4 workload: a small pytest suite with a little I/O per test."""
import json
import pytest


@pytest.mark.parametrize("i", range(100))
def test_json_roundtrip(i):
    obj = {"i": i, "items": list(range(i % 17)), "name": f"item-{i}"}
    assert json.loads(json.dumps(obj)) == obj


@pytest.mark.parametrize("i", range(60))
def test_tmp_write_read(tmp_path, i):
    p = tmp_path / f"f{i}.txt"
    p.write_text("x" * (i + 1))
    assert p.read_text() == "x" * (i + 1)


@pytest.mark.parametrize("i", range(40))
def test_sort_and_format(i):
    data = [(k * 7919) % 101 for k in range(i + 5)]
    assert sorted(data) == sorted(data, key=lambda x: (x, 0))
    assert f"{i:04d}".isdigit()
