"""The model receives the public output shape, never computed fixture answers."""
import json

import pytest

from ci.gauntlet.benchmark.artifact_contracts import artifact_contract, artifact_schema
from ci.gauntlet.benchmark.catalog import BUSINESS_IDS


@pytest.mark.parametrize('workflow_id', sorted(BUSINESS_IDS))
def test_public_prompt_embeds_complete_data_schema_without_answer_loading(workflow_id, monkeypatch):
    from ci.gauntlet.benchmark import catalog
    def forbidden(*_):
        raise AssertionError('public interface must not load expected answers')
    monkeypatch.setattr(catalog,'load_oracle_fixture',forbidden)
    text = artifact_contract(workflow_id)
    _, separator, raw = text.partition('Public artifact data JSON Schema:\n')
    assert separator and json.loads(raw) == artifact_schema(workflow_id)
    schema = json.loads(raw)
    assert schema['properties']['workflow_id'] == {'const':workflow_id}
    assert set(schema['required']) == {'workflow_id','rows','source_ids','source_versions','visibility'}
    assert 'each persisted artifact' in text.lower()
    assert 'exclusion-decision references in at least one persisted artifact' in text
    for answer_id in ('lead-a','contact-a','account-a','peer-confidential'):
        assert answer_id not in raw


def test_sales_public_schema_rejects_multiple_contacts_in_one_artifact():
    from jsonschema import Draft202012Validator
    schema = artifact_schema('business-sales-lead-qualification')
    rows = schema['properties']['rows']
    assert rows['minItems'] == rows['maxItems'] == 1
    validator = Draft202012Validator(rows)
    assert list(validator.iter_errors([]))
    row = {'contact_id':'synthetic-contact','account_id':'synthetic-account',
           'fit':0,'intent':0,'timing':0,'score':0,'source_ids':['synthetic-source']}
    validator.validate([row])
    errors = list(validator.iter_errors([row,{**row,'contact_id':'another-synthetic-contact'}]))
    assert {error.validator for error in errors} == {'maxItems'}
