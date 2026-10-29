# In-place container gateway upgrade

`install.sh` is for a first installation, not an upgrade. It now refuses to run
when gateway control or runtime configuration already exists; it does not repair
an incomplete previous installation.

For an existing **standard single-file Compose installation**, first put a
reviewed release's source in the original installation directory without
discarding local changes. Keep the existing `.env` and `docker-compose.yml` in
that directory. The upgrade tool does not fetch, pull, reset, or clean source.
Run it from that release directory:

```sh
sudo python3 scripts/upgrade-container-gateway.py          # read-only preflight
sudo python3 scripts/upgrade-container-gateway.py --apply  # build and upgrade
```

Preflight inspects the existing running `sokrat-gateway`, its image and Compose
project. It checks the local Docker context, project directory and single Compose
file, host networking, environment, bind mounts, logging, restart policy, and
service account IDs. Shell-provided Compose variables are intentionally ignored
so they cannot override the installed `.env`. Configuration values are not
printed on a refusal. Unsupported or mismatched configurations are refused
before build or recreation; do not bypass that refusal with the first installer.

Apply rebuilds the gateway image and runs Compose `up` for that service only,
with `--no-deps --no-build`. It does not run the first installer, rewrite `.env`,
rotate credentials, reset state, open firewall ports, or manage unrelated
containers. The image entrypoint no longer recursively changes ownership or mode
of host bind mounts. Existing mounted FCM credentials, control configuration,
registry and other data remain in place; the application and provisioning worker
may still make their normal runtime writes. The image build can need network
access, and its source and dependency updates must be reviewed before use.

## Operational limits

- This supports the shipped host-network Compose layout with a running gateway,
  one local Unix-socket Docker context, the original project directory and no
  Compose override files. Custom mount, environment, account, network or other
  runtime differences require a separately reviewed migration. Preflight is not
  a comprehensive audit of every possible Docker host customization.
- Recreating the gateway interrupts its sessions and services. Schedule a window.
  Use a single deployment operator: the tool rechecks the container and rendered
  Compose configuration after building, but cannot lock out other Docker users.
  Build failure does not recreate the container, but a failure during or after
  Compose recreation can leave it unavailable. There is **no automatic rollback**;
  preflight prints the previous image ID for an operator's recovery plan. Keep
  independent backups of configuration and data before production upgrades.
- The command does not prove that the application is healthy after recreation.
  Inspect Compose status and logs and independently check the provider and tenant
  provisioning status. A healthy HTTP endpoint or loaded sender does not prove
  delivery, normal PBX call-path integration, or a killed-app wake.
- It does not install or validate a PBX call-path adapter. Including a future
  reviewed adapter in both the Docker image and the host provisioning bundle is
  still required; automatic wake setup across existing PBXs is **not yet ready**.
- The build updates the Compose image tag. It does not recreate other containers,
  but another deployment that independently uses that same tag could pick up the
  new image on its own later recreation; use a dedicated image tag for isolation.
- Tests use a fake Docker CLI and temporary fixtures; they do not constitute a
  real container upgrade or production acceptance test. No live VPS is touched.

Run the regression tests with `node --test test/container-upgrade.test.js`.
