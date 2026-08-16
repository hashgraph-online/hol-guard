#!/usr/bin/env python3
"""Reference stateful Cloud service for the HOL Guard MDM integration lab."""
import argparse, json, os
from pathlib import Path
from lab_common import CloudServer, Store

def main():
 p=argparse.ArgumentParser();p.add_argument('--host',default='0.0.0.0');p.add_argument('--port',type=int,default=8090);p.add_argument('--database',type=Path,default=Path('/state/cloud.sqlite3'));p.add_argument('--signing-key',type=Path,default=Path('/state/cloud-key.pem'));a=p.parse_args()
 seeds=json.loads(os.environ.get('HOL_MDM_LAB_DEVICE_SEEDS','[]'));server=CloudServer((a.host,a.port),Store(a.database,a.signing_key,seeds),os.environ.get('HOL_MDM_LAB_ADMIN_TOKEN','hol-guard-mdm-lab-admin'));server.serve_forever()
if __name__=='__main__':main()
