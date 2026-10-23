"""Grow an existing VM disk only after capacity and guest filesystem checks."""
import shutil

GIB=1024**3


def plan(args, state, target, inventory):
    requested=getattr(args,'vm_disk_gib',None)
    current=inventory.get('disk')
    if requested is None:
        if type(current) is int and current>0 and current%GIB==0:
            target['vm_disk_gib']=current//GIB
        return []
    if type(current) is not int or current<=0 or current%GIB:
        raise ValueError('existing VM disk allocation cannot be verified')
    if type(requested) is not int or not 24<=requested<=256 or requested*GIB<current:
        raise ValueError('VM disk must be 24–256 GiB and cannot shrink the existing disk')
    growth=requested*GIB-current
    if shutil.disk_usage(state).free-growth<target['host_disk_floor_gib']*GIB:
        raise ValueError('disk growth would exceed available host headroom')
    target['vm_disk_gib']=requested
    return ['--disk='+str(requested)] if growth else []


def verify(args, target, inventory, guest):
    if getattr(args,'vm_disk_gib',None) is None:
        return
    size=target['vm_disk_gib']
    if inventory.get('disk')!=size*GIB or guest.get('disk_total',0)<(size-3)*GIB:
        raise RuntimeError('VM disk or guest filesystem did not confirm growth; observer remains stopped')
