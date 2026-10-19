"""Fixed trusted capability probe; no Guard imports, candidate or model calls."""
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    root = Path(tempfile.mkdtemp(prefix='hol-initializer-probe-',dir='/tmp'))
    lower,upper,work = (root/name for name in ('lower','upper','work'))
    for path in (lower,upper,work,lower/'d'):
        path.mkdir()
    (lower/'d/old').write_text('')
    (lower/'gone').write_text('')
    argv = ['/usr/bin/bwrap','--die-with-parent','--new-session','--unshare-all',
            '--cap-drop','ALL','--proc','/proc','--dev','/dev','--tmpfs','/tmp']
    for name in ('/usr','/bin','/sbin','/lib','/lib32','/lib64'):
        path = Path(name)
        if path.is_symlink():
            argv += ['--symlink',os.readlink(path),name]
        elif path.exists():
            argv += ['--ro-bind',name,name]
    for name in ('alternatives','group','hosts','ld.so.cache','localtime','nsswitch.conf',
                 'passwd','protocols','services'):
        argv += ['--ro-bind-try','/etc/'+name,'/etc/'+name]
    argv += ['--overlay-src',str(lower),'--overlay',str(upper),str(work),str(lower),
             '--chdir',str(lower),'--','/bin/sh','-c',
             'echo x > new && rm gone && rm -rf d && mkdir d']
    result = subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=7,
                            env={'PATH':'/usr/bin:/bin'})
    record = {'schema':'root-initializer-nested-probe.v1','argv':argv,'returncode':result.returncode,
              'stdout':result.stdout.decode(errors='replace')[:8192],
              'stderr':result.stderr.decode(errors='replace')[:8192],
              'status':Path('/proc/self/status').read_text(),
              'mountinfo':Path('/proc/self/mountinfo').read_text(),
              'overlay_new_file':(upper/'new').exists(),'model_exercised':False,
              'guard_exercised':False,'candidate_code_executed':False,'qualification_eligible':False}
    print(json.dumps(record,sort_keys=True),flush=True)


if __name__=='__main__':
    main()
