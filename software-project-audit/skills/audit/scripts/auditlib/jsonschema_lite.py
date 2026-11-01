"""Minimal JSON-schema validator (subset) returning error strings."""
from __future__ import annotations

import re

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "null": lambda v: v is None,
}


def validate(instance, schema: dict) -> list[str]:
    errors: list[str] = []
    _check(instance, schema, schema, "", errors)
    return errors


def _resolve(ref: str, root: dict) -> dict:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise ValueError("unsupported $ref: %s" % ref)
    return root["$defs"][ref[len(prefix):]]


def _esc(key) -> str:
    return str(key).replace("~", "~0").replace("/", "~1")


def _check(inst, schema, root, ptr, errors) -> None:
    if "$ref" in schema:
        schema = _resolve(schema["$ref"], root)
    where = ptr or "/"
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[t](inst) for t in types):
            errors.append("%s: expected type %s, got %s" % (where, "|".join(types), type(inst).__name__))
            return
    if "enum" in schema and inst not in schema["enum"]:
        errors.append("%s: %r is not one of enum %s" % (where, inst, schema["enum"]))
    if "oneOf" in schema:
        matches = sum(1 for s in schema["oneOf"] if not _sub(inst, s, root, ptr))
        if matches != 1:
            errors.append("%s: must match exactly one of oneOf (matched %d)" % (where, matches))
    if isinstance(inst, str) and "pattern" in schema:
        if not re.search(schema["pattern"], inst):
            errors.append("%s: %r does not match pattern %s" % (where, inst, schema["pattern"]))
    if _TYPES["number"](inst):
        if "minimum" in schema and inst < schema["minimum"]:
            errors.append("%s: %r is less than minimum %s" % (where, inst, schema["minimum"]))
        if "maximum" in schema and inst > schema["maximum"]:
            errors.append("%s: %r is greater than maximum %s" % (where, inst, schema["maximum"]))
    if isinstance(inst, dict):
        for name in schema.get("required", []):
            if name not in inst:
                errors.append("%s: missing required property '%s'" % (where, name))
        props = schema.get("properties", {})
        for k, v in inst.items():
            if k in props:
                _check(v, props[k], root, "%s/%s" % (ptr, _esc(k)), errors)
            elif schema.get("additionalProperties") is False:
                errors.append("%s: additional property '%s' not allowed" % (where, k))
    if isinstance(inst, list):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            errors.append("%s: expected at least %d items, got %d" % (where, schema["minItems"], len(inst)))
        if "items" in schema:
            for i, v in enumerate(inst):
                _check(v, schema["items"], root, "%s/%d" % (ptr, i), errors)


def _sub(inst, schema, root, ptr) -> list[str]:
    errs: list[str] = []
    _check(inst, schema, root, ptr, errs)
    return errs
