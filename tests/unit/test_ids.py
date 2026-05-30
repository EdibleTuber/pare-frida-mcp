import pytest
from pare_frida_mcp.ids import new_session_id, validate_session_id

def test_new_id_is_uuid_shaped():
    sid = new_session_id()
    assert validate_session_id(sid) == sid

@pytest.mark.parametrize("bad", ["../../etc", "abc/def", "", "..", "a"*40, "X"*36])
def test_rejects_traversal_and_junk(bad):
    with pytest.raises(ValueError):
        validate_session_id(bad)
