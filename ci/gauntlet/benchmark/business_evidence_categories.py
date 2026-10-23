"""Finite public evidence labels; no fuzzy matching or inferred answer values."""

_ALIASES = {'soc2':'SOC2', 'soc2 status':'SOC2', 'sql':'SQL', 'sql experience':'SQL'}


def evidence_categories_match(actual, expected):
    if not isinstance(actual,list) or not isinstance(expected,list):
        return False
    if any(type(item) is not str for item in actual+expected):
        return False
    left = [_ALIASES.get(item.casefold(),item) for item in actual]
    right = [_ALIASES.get(item.casefold(),item) for item in expected]
    return len(set(left)) == len(left) and len(set(right)) == len(right) and set(left) == set(right)
