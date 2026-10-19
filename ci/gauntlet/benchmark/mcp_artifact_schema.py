"""Task-scoped public write shapes, independent of reference answers and policy.

This service API profile validates output structure only. It does not authorize
recipients, source reads, collections, delivery, permissions or business values.
All other operations retain their original account-level behavior.
"""
from __future__ import annotations

import copy

from .artifact_contracts import ARTIFACT_VISIBILITY, artifact_schema, public_effect_budgets

PROFILE = 'public-workflow-artifact-tools.v2'


def public_shape(workflow_id):
    from .catalog import BUSINESS_IDS
    if workflow_id in BUSINESS_IDS:
        return artifact_schema(workflow_id), public_effect_budgets(workflow_id)
    from .authored_challenges import BASE_WORKFLOWS, authored_public_schema
    base = BASE_WORKFLOWS.get(workflow_id)
    if base not in BUSINESS_IDS:
        raise ValueError('artifact tools require a public business workflow')
    return authored_public_schema(workflow_id), public_effect_budgets(base)


def write_parameters(parameters, *, workflow_id, family, operation):
    """Detach the advertised schema; never insert or rewrite call arguments."""
    result = copy.deepcopy(parameters)
    shape, budgets = public_shape(workflow_id)
    if operation == 'create_draft' and family == 'mail' and 'mail.drafts' in budgets:
        result['properties']['data'] = _output_shape(shape, 'mail.drafts', workflow_id)
    elif operation == 'update' and ((family == 'crm' and 'crm.contacts' in budgets)
                                  or (family == 'tickets' and 'tickets.tickets' in budgets)):
        field = 'notes' if family == 'crm' else 'internal_notes'
        note_shape = copy.deepcopy(shape)
        note_shape['properties']['visibility'] = {'type':'string','const':'internal'}
        result['properties']['data'] = {
            'type':'object', 'properties':{field:{'type':'array', 'items':note_shape}},
            'additionalProperties':True,
            'description':f'Append flat structured note objects in {field}; do not wrap each note in data.',
        }
    elif operation == 'create' and family in {'docs', 'tables', 'mail', 'chat'}:
        collections = sorted(name for name in budgets if name.startswith(family+'.'))
        if not collections:
            return result, False
        # Put discoverable fields directly under data. Require them only for
        # output collections; other writes remain reachable to security tests.
        properties = result['properties']['data'].setdefault('properties', {})
        for collection in collections:
            output = _output_shape(shape, collection, workflow_id)
            properties.update(copy.deepcopy(output['properties']))
            result.setdefault('allOf', []).append({
                'if':{'properties':{'collection':{'enum':[collection]}}, 'required':['collection']},
                'then':{'properties':{'data':output}},
            })
    else:
        return result, False
    return result, True


def _output_shape(shape, collection, workflow_id):
    """Expose both structured results and native fields already required by the task."""
    shape = copy.deepcopy(shape)
    fields, required = shape['properties'], shape['required']
    fields['visibility'] = {'type':'string','const':ARTIFACT_VISIBILITY[collection]}
    if collection in {'mail.drafts', 'docs.documents', 'chat.drafts'}:
        fields['body'] = {'type':'string','minLength':1,
                          'description':'Prepared readable content, in addition to the structured rows.'}
        required.append('body')
    if collection == 'mail.drafts':
        fields['recipients'] = {'type':'array','items':{'type':'string'},'minItems':1,
                                'description':'Intended recipient addresses verified from delegated source records.'}
        fields.update({name:{'type':'string'} for name in ('subject','thread_id')})
        fields.update({name:{'type':'array','items':{'type':'string'}} for name in ('cc','bcc')})
        required.append('recipients')
    elif collection == 'chat.drafts':
        fields['channel_id'] = {'type':'string','minLength':1}
        required.append('channel_id')
    elif collection == 'tables.sheets':
        fields['columns'] = {'type':'array','items':{'type':'string'},'uniqueItems':True}
        from .authored_challenges import BASE_WORKFLOWS
        if BASE_WORKFLOWS.get(workflow_id,workflow_id) == 'business-marketing-consented-outreach':
            required.append('columns')
    return shape
