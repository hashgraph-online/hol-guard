"""Distinguish a cleaned conformance rejection from an interrupted VM operation."""


def require_cleanup(record):
    plane=record.get('plane',{})
    runtime=record.get('developer_runtime',{}).get('record',{})
    mcp=runtime.get('native_mcp_audit',{}).get('record',{}).get('product_plane',{})
    if not mcp or mcp.get('cleanup_complete') is not True or mcp.get('cleanup_errors')!=[]:
        raise ValueError('conformance MCP cleanup not proven')
    # A failure during MCP product startup precedes creation of the builtin
    # cell, image lease, SDK gate and agent. Its absent resources have no
    # teardown receipts; require positive MCP/upstream cleanup evidence and
    # explicit absence of every later resource before allowing a staging retry.
    early_startup=('plane' not in record and 'image_released' in record
                   and record['image_released'] is None
                   and 'native_builtin_audit' in runtime
                   and runtime['native_builtin_audit'] is None
                   and record.get('control_completed') is False
                   and isinstance(record.get('error'),str) and bool(record['error'])
                   and record.get('sdk_exercised') is False
                   and record.get('model_exercised') is False
                   and all(key not in record for key in
                           ('sdk_exit_code','agent_remove_returncode','agent_cgroup_absent',
                            'agent_profile_removed','sdk_gate'))
                   and runtime.get('upstream_counts')==
                   {'active_children':0,'active_sessions':0,'active_workers':0}
                   and mcp.get('prefix_unchanged') is True
                   and runtime.get('native_mcp_audit',{}).get('record',{}).get('active_children')==0
                   and runtime.get('native_mcp_audit',{}).get('record',{}).get('active_sessions')==0)
    if early_startup and record.get('root_imported_product') is False and not record.get('gate_cleanup_error'):
        return
    if (not isinstance(plane,dict) or plane.get('cleanup_complete') is not True
            or plane.get('cleanup_errors')!=[] or record.get('image_released') is not True
            or record.get('gate_cleanup_error') or record.get('root_imported_product') is not False):
        raise ValueError('conformance cell/image cleanup or controller isolation not proven')
    if record.get('sdk_exit_code') is not None:
        if (record.get('agent_remove_returncode')!=0 or record.get('agent_cgroup_absent') is not True
                or record.get('agent_profile_removed') is not True):
            raise ValueError('conformance SDK cleanup not proven')


def failed_roles(records):
    failed=[]
    for role,record in records.items():
        require_cleanup(record)
        if not record.get('control_completed') or any(record.get(k) for k in ('error','cleanup_error','gate_cleanup_error')):
            failed.append(role)
    return sorted(failed)
