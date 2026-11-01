from auditlib.jsonschema_lite import validate


def ok(i, s):
    assert validate(i, s) == []


def bad(i, s, frag=""):
    errs = validate(i, s)
    assert errs and frag in " ".join(errs), errs


def test_type():
    ok(1, {"type": "integer"})
    bad("1", {"type": "integer"}, "type")
    bad(True, {"type": "integer"})
    ok(None, {"type": ["string", "null"]})
    bad(3, {"type": ["string", "null"]})


def test_required_properties_and_pointer():
    s = {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}
    ok({"a": "x"}, s)
    bad({}, s, "'a'")
    errs = validate([{"a": 1}], {"type": "array", "items": s})
    assert errs[0].startswith("/0/a")


def test_additional_properties():
    s = {"type": "object", "properties": {"a": {}}, "additionalProperties": False}
    ok({"a": 1}, s)
    bad({"a": 1, "b": 2}, s, "'b'")


def test_items_minitems():
    s = {"type": "array", "minItems": 1, "items": {"type": "string"}}
    ok(["a"], s)
    bad([], s, "at least")
    bad([1], s, "/0")


def test_enum_pattern():
    ok("a", {"enum": ["a", "b"]})
    bad("c", {"enum": ["a", "b"]}, "enum")
    ok("AUD-001", {"pattern": r"^AUD-\d{3}$"})
    bad("AUD-1", {"pattern": r"^AUD-\d{3}$"}, "pattern")


def test_min_max():
    s = {"type": "integer", "minimum": 0, "maximum": 4}
    ok(2, s)
    bad(-1, s, "minimum")
    bad(5, s, "maximum")


def test_one_of():
    s = {"oneOf": [{"type": "integer"}, {"enum": ["x"]}]}
    ok(1, s)
    ok("x", s)
    bad("y", s, "oneOf")


def test_ref_resolution():
    s = {"$defs": {"n": {"type": "integer"}}, "type": "array", "items": {"$ref": "#/$defs/n"}}
    ok([1], s)
    bad(["a"], s, "/0")
