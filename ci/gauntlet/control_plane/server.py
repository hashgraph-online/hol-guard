"""Read-only dashboard; no GitHub credentials, Docker socket or shell API."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

STATIC = Path(__file__).parent/'static'
SERVICE = 'hol-gauntlet-dashboard'


def identity(root):
    try:
        return json.loads((Path(root)/'dashboard-id.json').read_text())['instance_id']
    except (OSError, ValueError, KeyError, TypeError):
        return None


def snapshot(root):
    path = Path(root)/'snapshot.json'
    try:
        if path.stat().st_size > 4*1024**2:
            raise ValueError('snapshot too large')
        value = json.loads(path.read_text())
        age = max(0, time.time() - value['updated_at'])
        value['collector_age_seconds'] = round(age, 1)
        value['collector_status'] = 'online' if age < 90 else 'stale'
        try:
            live = Path(root)/'live.json'
            if live.exists() and live.stat().st_size <= 64*1024:
                row = json.loads(live.read_text())
                if (isinstance(row,dict) and row.get('schema') == 'hol-gauntlet-live-operations.v1'
                        and isinstance(row.get('updated_at'),(int,float))):
                    row['telemetry_status'] = ('stale' if row.get('status') in
                        {'queued','provider-startup','model-ready','vm-preflight','prepared','running'}
                        and time.time()-row['updated_at']>90 else 'current')
                    value['live_e2e'] = row
        except (OSError,ValueError,TypeError):
            pass
        try:
            probe = Path(root)/'feature-ai.json'
            if probe.exists() and probe.stat().st_size <= 64*1024:
                row = json.loads(probe.read_text())
                if (isinstance(row,dict) and row.get('schema') == 'hol-gauntlet-live-operations.v1'
                        and row.get('profile') in {'feature-ai', 'feature-ai-protocol'}
                        and isinstance(row.get('updated_at'),(int,float))):
                    if (row['profile'] == 'feature-ai-protocol' and row.get('status') == 'passed'
                            and row.get('model_ingestion_proven') is None):
                        cells = row.get('cells', [])
                        row['model_ingestion_proven'] = (len(cells) == 2 and all(
                            c.get('model_ingestion_proven') is True
                            and c.get('protocol_exposure_stage') == 'model-context-forwarded'
                            for c in cells))
                    row['telemetry_status'] = ('stale' if row.get('status') in
                        {'queued','provider-startup','model-ready','vm-preflight','prepared','running'}
                        and time.time()-row['updated_at']>90 else 'current')
                    value['feature_ai'] = row
        except (OSError,ValueError,TypeError):
            pass
        try:
            feature = Path(root)/'feature-audit.json'
            if feature.exists() and feature.stat().st_size <= 128*1024:
                row = json.loads(feature.read_text())
                if (isinstance(row, dict) and row.get('schema') == 'hol-gauntlet-feature-operations.v1'
                        and isinstance(row.get('updated_at'), (int, float))):
                    row['telemetry_status'] = ('stale' if row.get('status') in
                        {'starting', 'running'} and time.time()-row['updated_at'] > 90 else 'current')
                    value['feature_audit'] = row
        except (OSError, ValueError, TypeError):
            pass
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return {'collector_status': 'unavailable', 'collector_age_seconds': None, 'jobs': [],
                'github': {'status': 'unknown'}, 'gate': {'required': None},
                'admission_reasons': ['Host collector has not published a valid snapshot']}


def handler(root):
    class Dashboard(BaseHTTPRequestHandler):
        def do_GET(self):
            # No cross-origin access or permissive CORS. Local browser use only.
            host = self.headers.get('Host', '').split(':')[0]
            if host not in {'localhost', '127.0.0.1'}:
                self.send_error(403)
                return
            path = urlsplit(self.path).path
            if path in {'/api/status', '/healthz'}:
                value = snapshot(root)
                if path == '/healthz':
                    value = {'service': SERVICE, 'instance_id': identity(root),
                             'server': 'online', 'collector': value['collector_status']}
                body, content = json.dumps(value, allow_nan=False).encode(), 'application/json'
            elif path in {'/', '/app.js', '/style.css'}:
                name = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[path]
                body = (STATIC/name).read_bytes()
                content = {'/': 'text/html; charset=utf-8', '/app.js': 'text/javascript',
                           '/style.css': 'text/css'}[path]
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', content)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass
    return Dashboard


def serve(root, bind='127.0.0.1', port=8791):
    server = ThreadingHTTPServer((bind, port), handler(root))
    print(f'Gauntlet dashboard: http://127.0.0.1:{port}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8791)
    args = parser.parse_args()
    serve(args.state, args.bind, args.port)
