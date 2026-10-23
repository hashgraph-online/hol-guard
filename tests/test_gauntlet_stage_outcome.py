from copy import deepcopy
import unittest

from ci.gauntlet.control_plane.stage_outcome import failed_roles


def specimen():
    return {'control_completed':True,'root_imported_product':False,'image_released':True,
            'sdk_exit_code':0,'agent_remove_returncode':0,'agent_cgroup_absent':True,
            'agent_profile_removed':True,'plane':{'cleanup_complete':True,'cleanup_errors':[]},
            'developer_runtime':{'record':{'native_mcp_audit':{'record':{'product_plane':
                {'cleanup_complete':True,'cleanup_errors':[]}}}}}}


def early_startup_specimen():
    return {'control_completed':False,'sdk_exercised':False,'model_exercised':False,
            'error':'TimeoutError: product capture exceeded deadline',
            'image_released':None,'root_imported_product':False,
            'developer_runtime':{'record':{
                'native_builtin_audit':None,
                'upstream_counts':{'active_children':0,'active_sessions':0,'active_workers':0},
                'native_mcp_audit':{'record':{'active_children':0,'active_sessions':0,
                    'product_plane':{'cleanup_complete':True,'cleanup_errors':[],
                                     'prefix_unchanged':True}}}}}}


class OutcomeTests(unittest.TestCase):
    def test_cleaned_product_failure_is_terminal_but_never_conformant(self):
        good=specimen();bad=deepcopy(good)
        bad.update(control_completed=False,error='SDK rejected boundary',sdk_exit_code=1)
        self.assertEqual(failed_roles({'success':good,'boundary':bad}),['boundary'])

    def test_uncertain_cell_sdk_mcp_or_root_isolation_always_halts(self):
        rows=[]
        for field,bad in [('image_released',False),('agent_remove_returncode',1),
                          ('agent_cgroup_absent',False),('agent_profile_removed',False),
                          ('root_imported_product',True),('gate_cleanup_error','survived')]:
            row=specimen();row[field]=bad;rows.append(row)
        row=specimen();row['plane']['cleanup_complete']=False;rows.append(row)
        row=specimen();row['developer_runtime']['record']['native_mcp_audit']['record']['product_plane']['cleanup_errors']=['survived'];rows.append(row)
        for record in rows:
            with self.subTest(record=record),self.assertRaises(ValueError):
                failed_roles({'boundary':record})

    def test_success_needs_all_cleanup_evidence(self):
        self.assertEqual(failed_roles({'success':specimen()}),[])
        with self.assertRaises(ValueError):
            failed_roles({'success':{'control_completed':True}})

    def test_cleaned_pre_builtin_startup_failure_can_be_retried(self):
        self.assertEqual(failed_roles({'boundary':early_startup_specimen()}),['boundary'])

    def test_pre_builtin_retry_requires_absent_later_resources_and_drained_mcp(self):
        rows=[]
        for key,value in [('agent_remove_returncode',0),('sdk_exit_code',0),
                          ('image_released',False),('root_imported_product',True),
                          ('sdk_exercised',True)]:
            row=early_startup_specimen();row[key]=value;rows.append(row)
        row=early_startup_specimen()
        row['developer_runtime']['record']['native_builtin_audit']={}
        rows.append(row)
        row=early_startup_specimen()
        row['developer_runtime']['record']['upstream_counts']['active_workers']=1
        rows.append(row)
        row=early_startup_specimen()
        row['developer_runtime']['record']['native_mcp_audit']['record']['product_plane']['prefix_unchanged']=False
        rows.append(row)
        for record in rows:
            with self.subTest(record=record),self.assertRaises(ValueError):
                failed_roles({'boundary':record})
