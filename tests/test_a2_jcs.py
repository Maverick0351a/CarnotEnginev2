from signet import jcs

def test_jcs_deterministic_object_order():
    obj = {'b': 2, 'a': 1}
    c = jcs.canonicalize(obj)
    assert c == b'{"a":1,"b":2}'


def test_jcs_numbers_formats():
    # simple integer
    assert jcs.canonicalize(0).decode() == '0'
    assert jcs.canonicalize(123).decode() == '123'
    # floats
    assert jcs.canonicalize(1.0).decode() == '1'
    assert jcs.canonicalize(0.0000001).decode().endswith('e-7') or jcs.canonicalize(0.0000001).decode()=='1e-7'


def test_jcs_nested():
    obj = {'z': [3, 2, 1], 'a': {'x': True, 'y': None}}
    c = jcs.canonicalize(obj)
    assert c == b'{"a":{"x":true,"y":null},"z":[3,2,1]}'
