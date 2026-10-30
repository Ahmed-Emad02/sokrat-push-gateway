#!/usr/bin/env python3
"""Promote the reviewed host enrollment service beside a Docker gateway.

Dry-run by default. --apply only installs files: it never initializes secrets,
restarts FRP/Docker, opens ports, migrates a PBX, or enables services. The operator
must explicitly initialize and validate the staged service before activation.
"""
import argparse
import importlib.util
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location('promotion',root/'scripts/install-provisioning-worker.py')
    promotion = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(promotion)
    names = ('tunnel-enrollment.py','tunnel_media.py','tunnel_media_material.py',
             'install-media-link.py','check-tunnel-readiness.py','sync-tenant-runtime.py')
    installs = [(promotion.BUNDLE/name,promotion.reviewed_source(root/'scripts'/name),0o755)
                for name in names]
    installs.append((promotion.BUNDLE/'provisioning-firewall-local.py',
                     promotion.reviewed_source(root/'docker/provisioning-firewall-local.py'),0o755))
    unit = 'sokrat-tunnel-enrollment.service'
    installs.append((Path('/etc/systemd/system')/unit,promotion.reviewed_source(root/'systemd'/unit),0o644))
    for target,content,_ in installs:
        promotion.safe_target(target)
        if target.suffix=='.py':compile(content,str(target),'exec')
    if not args.apply:
        print('Dry-run: reviewed host enrollment bundle validated; no writes or service changes')
        return
    import os
    import subprocess
    if os.geteuid()!=0:raise ValueError('Root required')
    active = subprocess.run(['systemctl','is-active','--quiet',unit],timeout=15).returncode==0
    if active:raise ValueError('Stop enrollment explicitly before promoting a new bundle')
    promotion.promote(installs)
    print('Enrollment remains disabled; initialize and validate explicitly before enabling')


if __name__=='__main__':
    main()
