# Vendored MeshDrive configs for snap builds (LXD).

Snapcraft packs the project into a VM and may omit untracked or gitignored
files. This tree is a fallback copy of `overlay/opt/meshdrive/` so
`snapcraft pack --use-lxd` still finds `etc/` + `systemd/`.

Refresh after editing overlay:

```bash
rsync -a --delete overlay/opt/meshdrive/ snap/local/opt/meshdrive/
```

Python sources still come from `src/` — those must be present in the packed
tree (commit them). Same for `packaging/` and `pyproject.toml`.
