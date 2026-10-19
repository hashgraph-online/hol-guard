"""Pinned allocator provisioning keeps product bytes and kernel limits intact."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from ci.gauntlet.control_plane import executor_image as module
from ci.gauntlet.benchmark import native_product_container, product_vm_rootfs


class ExecutorImageTests(unittest.TestCase):
    def test_preload_rejects_any_path_other_than_fixed_image_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);system=root/'system';new=root/'new'
            (system/'etc').mkdir(parents=True);(new/'etc').mkdir(parents=True)
            preload=system/'etc/ld.so.preload';preload.write_text('/tmp/candidate.so\n')
            with patch.object(product_vm_rootfs,'_trusted'),self.assertRaises(ValueError):
                product_vm_rootfs._allocator_policy(system,new)
            self.assertFalse((new/'etc/ld.so.preload').exists())
            library=system/'usr/lib/hol-gauntlet/libmalloc-policy.so'
            library.parent.mkdir(parents=True);library.write_bytes(b'trusted fixture')
            preload.write_text('/usr/lib/hol-gauntlet/libmalloc-policy.so\n')
            with patch.object(product_vm_rootfs,'_trusted'):
                product_vm_rootfs._allocator_policy(system,new)
            self.assertEqual((new/'etc/ld.so.preload').read_bytes(),preload.read_bytes())
            self.assertEqual((new/'etc/ld.so.preload').stat().st_mode&0o777,0o444)

    def test_retained_image_must_match_sources_architecture_and_full_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            controller=Path(temporary);context=controller/'ci/gauntlet/control_plane/allocator-image'
            context.mkdir(parents=True)
            names=('Executor.Dockerfile','malloc_policy.c','malloc.preload')
            for name in names:(context/name).write_bytes(name.encode())
            sources={name:hashlib.sha256((context/name).read_bytes()).hexdigest() for name in names}
            receipt=controller/'executor-image.json'
            receipt.write_text(json.dumps({'image_id':'sha256:'+'a'*64,'sources':sources}))
            observation=[{'Id':'a'*64,'Os':'linux','Architecture':'arm64'}]
            present=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
            with patch.object(module,'run',return_value=json.dumps(observation).encode()), \
                 patch.object(module.subprocess,'run',return_value=present):
                self.assertEqual(module.image(controller,lambda *a,**k:None),'sha256:'+'a'*64)
            observation[0]['Architecture']='amd64'
            with patch.object(module,'run',return_value=json.dumps(observation).encode()), \
                 patch.object(module.subprocess,'run',return_value=present),self.assertRaises(ValueError):
                module.image(controller,lambda *a,**k:None)
            (context/'malloc_policy.c').write_text('changed')
            with patch.object(module,'run') as run,self.assertRaises(ValueError):
                module.image(controller,lambda *a,**k:None)
            run.assert_not_called()

    def test_missing_retained_image_is_rebuilt_only_at_its_original_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            controller=Path(temporary);context=controller/'ci/gauntlet/control_plane/allocator-image'
            context.mkdir(parents=True)
            names=('Executor.Dockerfile','malloc_policy.c','malloc.preload')
            for name in names:(context/name).write_bytes(name.encode())
            sources={name:hashlib.sha256((context/name).read_bytes()).hexdigest() for name in names}
            identifier='sha256:'+'a'*64
            receipt=controller/'executor-image.json'
            receipt.write_text(json.dumps({'image_id':identifier,'sources':sources}))
            absent=SimpleNamespace(returncode=1,stdout=b'',stderr=b'')
            observed=json.dumps([{'Id':identifier,'Os':'linux','Architecture':'arm64'}]).encode()
            with patch.object(module.subprocess,'run',return_value=absent), \
                 patch.object(module,'run',side_effect=[identifier.encode()+b'\n',observed]) as run:
                self.assertEqual(module.image(controller,lambda *a,**k:None),identifier)
            self.assertEqual(run.call_count,2)
            self.assertIn('--network=none',run.call_args_list[0].args[0])
            self.assertEqual(json.loads(receipt.read_text())['image_id'],identifier)
            with patch.object(module.subprocess,'run',return_value=absent), \
                 patch.object(module,'run',return_value=('sha256:'+'b'*64).encode()), \
                 self.assertRaisesRegex(ValueError,'differs from retained identity'):
                module.image(controller,lambda *a,**k:None)

    def test_new_template_and_artifacts_preserve_original_baseline_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);controller=root/'controller';controller.mkdir()
            old=root/'old-cell/public';old.mkdir(parents=True)
            dependencies=root/'alpha-dependencies';dependencies.mkdir()
            (old/'initializer').write_bytes(b'original initializer')
            (old/'actor.py').write_bytes(b'original actor')
            template={'assets':{'private_cell':{'path':'old-cell','sha256':'a'*64},
                                'guard_prefix':{'path':'old-dependencies','sha256':'d'*64}},
                      'runtime':{'guard_executor_image_id':'sha256:'+'b'*64}}
            original=module.canonical(template)+b'\n';path=root/'baseline.json';path.write_bytes(original)
            settings={'controller_python':'/trusted/python','template_config':str(path),
                      'template_config_digest':hashlib.sha256(module.canonical(template)).hexdigest(),
                      'asset_root':str(root),'template_controller':'/trusted/original-controller',
                      'staging_dependency_prefix':str(dependencies),
                      'staging_dependency_prefix_digest':'e'*64}
            inputs=ModuleType('ci.gauntlet.benchmark.private_cell_campaign_inputs')
            inputs._sources=lambda:{'code/rootfs.py':b'new trusted constructor'}
            with patch.dict('sys.modules',{inputs.__name__:inputs}),patch.object(module.os,'geteuid',return_value=0), \
                 patch.object(module,'run',return_value=b'{"status":"verified"}'), \
                 patch.object(module,'image',return_value='sha256:'+'c'*64), \
                 patch.object(native_product_container,'root_prefix_digest',return_value='e'*64) as digest:
                result=module.install(controller,settings,lambda *a,**k:None)
                digest.assert_called_once_with(dependencies)
            updated=json.loads(Path(result['staging_template_config']).read_text())
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(updated['runtime']['guard_executor_image_id'],'sha256:'+'c'*64)
            self.assertEqual(updated['assets']['guard_prefix'],
                             {'path':'alpha-dependencies','sha256':'e'*64})
            artifacts=root/updated['assets']['private_cell']['path']
            self.assertEqual((artifacts/'public/initializer').read_bytes(),b'original initializer')
            self.assertEqual(hashlib.sha256((artifacts/'manifest.json').read_bytes()).hexdigest(),updated['assets']['private_cell']['sha256'])
