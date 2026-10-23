"""Trusted UID10004 child gate; no product import before outside measurement."""
import ctypes
import os
import sys

if __package__:
    from .product_cell_layout import load_layout
else:
    sys.path.insert(0,'/public')
    from ci.gauntlet.benchmark.product_cell_layout import load_layout


def main():
    if len(sys.argv)<2 or not sys.argv[1].startswith('/') or os.getuid()!=10004 or os.getgid()!=10004:
        raise ValueError('absolute product command and unprivileged actor required')
    layout=load_layout()
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(4,0,0,0,0)!=0:  # PR_SET_DUMPABLE
        raise OSError(ctypes.get_errno(),'lock child dumpability')
    os.write(1,b'HOL_PRODUCT_EXEC_READY_V1\n')
    if os.read(0,1)!=b'\x01':
        raise SystemExit(126)
    os.chdir(layout['workspace'])
    os.execve(sys.argv[1],sys.argv[1:],{'PATH':layout['path'],'HOME':'/product/home','LANG':'C.UTF-8',
                                     'MALLOC_ARENA_MAX':'2'})


if __name__=='__main__':
    main()
