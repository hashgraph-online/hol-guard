"""Nullable schema projection preserves original validation and argument text."""
import copy

import pytest
from jsonschema import Draft202012Validator

from ci.gauntlet.benchmark.mlx_nullable_tool_schema import parser_schema_view, verify_parser


def tool(property_schema):
    return [{'type':'function','function':{'name':'mail.create_draft',
        'parameters':{'type':'object','properties':{'tenant_id':property_schema}}}}]


@pytest.mark.parametrize('kind', ['string','integer','number','boolean','array','object'])
@pytest.mark.parametrize('reverse', [False, True])
def test_single_nullable_type_has_detached_parser_view(kind, reverse):
    types = [kind,'null'] if not reverse else ['null',kind]
    original = tool({'type':types,'title':'Public field','description':'Keep metadata'})
    before = copy.deepcopy(original)
    projected = parser_schema_view(original)
    assert original == before
    field = projected[0]['function']['parameters']['properties']['tenant_id']
    assert field == {'type':'object' if kind=='boolean' else kind,
                     'title':'Public field','description':'Keep metadata'}


@pytest.mark.parametrize('types', [['string','number','null'],['string','number'],['null','null'],
                                 ['string'],['string','string'],[True,'null'],['unknown','null']])
def test_ambiguous_invalid_or_nonnullable_types_are_unchanged(types):
    original = tool({'type':types})
    assert parser_schema_view(original) == original


def test_original_constraints_remain_authoritative():
    original = tool({'type':['string','null'],'minLength':3,'enum':['task-tenant',None]})
    before = copy.deepcopy(original)
    view = parser_schema_view(original)
    assert view[0]['function']['parameters']['properties']['tenant_id']['enum'] == ['task-tenant',None]
    schema = original[0]['function']['parameters']
    validator = Draft202012Validator(schema)
    for value in ['task-tenant',None]:
        validator.validate({'tenant_id':value})
    for value in ['peer-tenant','x',42,True,{}]:
        assert list(validator.iter_errors({'tenant_id':value}))
    assert original == before


def test_anyof_and_nested_data_are_not_reinterpreted():
    original = tool({'anyOf':[{'type':'string'},{'type':'null'}]})
    original[0]['function']['parameters']['properties']['data'] = {
        'type':'object','properties':{'embedded':{'type':['string','null']}}}
    assert parser_schema_view(original) == original


def test_unpinned_or_different_parser_is_refused():
    def other_parser(*_):
        raise AssertionError('must not call a parser to inspect identity')
    with pytest.raises(ValueError,match='pinned Qwen'):
        verify_parser(other_parser,'a'*64)


def test_missing_optional_tool_metadata_remains_unchanged():
    original = [{}, {'function':None}, {'function':{'parameters':None}}]
    assert parser_schema_view(original) == original
