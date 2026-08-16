from __future__ import annotations
import importlib.util,sys,threading
from pathlib import Path
ROOT=Path(__file__).parents[1];LAB=ROOT/'scripts/mdm/cloud-lab';sys.path.insert(0,str(LAB))
from device_runtime import Device,DeviceServer
from lab_common import CloudServer,Store
from orchestrator import orchestrate

def proxy_module():
 spec=importlib.util.spec_from_file_location('mdm_fault_proxy',LAB/'fault_proxy.py');module=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(module);return module

def serve(server): threading.Thread(target=server.serve_forever,daemon=True).start();return server

def test_real_http_multi_device_cloud_control_loop(tmp_path:Path):
 seeds=[{'workspaceId':'workspace-mdm-cloud-lab','deviceId':f'device-{c}','installationGeneration':c*32,'token':f'enrollment-token-device-{c}'} for c in 'abc']
 cloud=serve(CloudServer(('127.0.0.1',0),Store(tmp_path/'cloud.sqlite3',tmp_path/'cloud-key.pem',seeds),'admin'));cloud_url=f'http://127.0.0.1:{cloud.server_port}'
 proxy=proxy_module();faults=proxy.FaultState('admin');gateway=serve(proxy.FaultProxyServer(('127.0.0.1',0),upstream=cloud_url,state=faults,verbose=False));proxy_url=f'http://127.0.0.1:{gateway.server_port}'
 servers=[cloud,gateway];urls={}
 try:
  for c in 'abc':
   root=tmp_path/f'device-{c}';device=Device(root,proxy_url,'workspace-mdm-cloud-lab',f'device-{c}',c*32,f'enrollment-token-device-{c}',root/'policy.json');server=serve(DeviceServer(('127.0.0.1',0),device));servers.append(server);urls[f'device-{c}']=f'http://127.0.0.1:{server.server_port}'
  report=orchestrate(cloud_url,proxy_url,urls,'admin',tmp_path/'report.json')
  assert report['healthy'] is True;assert report['stepCount']>=25;assert all(x['passed'] for x in report['steps']);assert report['nativeCertification']['outcome']=='not-evaluated';assert (tmp_path/'report.json').exists()
 finally:
  for server in reversed(servers):server.shutdown();server.server_close()
