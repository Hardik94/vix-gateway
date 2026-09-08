# Identity upgrade: free local users → paid LDAP (MeshDrive 2.1)

## Recommendation (hybrid — what we ship)

**Do not redesign free-tier local UIDs to match the full workbook.local tree up front.**

| Stage | Identity | Login | Home data |
|-------|----------|-------|-----------|
| **Free** | `local_username` in `auth.yaml` + Filebrowser | Local only | `/opt/meshdrive/var/homes/<user>/private` (and/or bucket-scoped private) |
| **Paid activate** | Allocate stable LDAP `uidNumber`; write `identity_map.yaml` | Local **and** LDAP/SSSD | Same tree; `/home/users/<uidNumber>` → symlink to local home |
| **Remote LDAP** | Only mapped paid accounts exist in LDAP | Remote login uses LDAP uid | Same files via symlink / NFS / JuiceFS |
| **Downgrade** | Keep local auth + homes; stop SSSD; LDAP entries can remain disabled | Local still works | No data migration |

### Why this is better than “org UIDs from day one”

1. Free installs stay simple (no OpenLDAP required).
2. Usernames stay stable → Filebrowser and MCP keep working across upgrade.
3. Dual UID + symlink avoids rewriting ownership on existing files.
4. Argon2 password hashes **cannot** be copied into LDAP `{SSHA}` — force a one-time password set or invite flow on paid upgrade (script never invents a silent password clone).

### Flow

```text
auth.yaml users
    │
    ▼
scripts/ldap/export_local_users.py  →  identity_map.yaml + users.ldif
    │
    ▼
ldapadd on remote / hub LDAP (workbook.local org)
# or POST identity map → https://…/v1/provision  (authelia-fb-2.0)
    │
    ▼
scripts/ldap/link_homes.py --apply
    │
    ▼
meshdrive cluster configure  (SSSD) + license activate (HTTPS → authelia-fb-2.0)
```

Tooling:

- Device: [`scripts/ldap/`](../scripts/ldap/) — export map + dual-UID homes
- **Control plane:** [`../../authelia-fb-2.0/`](../../authelia-fb-2.0/) — OpenLDAP, Authelia, `/v1/provision`, license API
- Homes helper: [`src/meshdrive/storage/homes.py`](../src/meshdrive/storage/homes.py) — private + shared layout on JuiceFS buckets

---

## Org structure (paid)

Base: `dc=workbook,dc=local`

- `ou=groups` — platform roles (`sysadmins`, `partners_all`)
- `ou=consumers` — B2C families (`FAM-*`)
- `ou=enterprises` — direct B2B (`COMP-*`)
- `ou=partners` — resellers + `ou=managed_customers`

Each tenant gets posix groups for ADMIN / EDITOR|STAFF / VIEWER and `cn=users` for accounts.

Generate skeleton:

```bash
python3 scripts/ldap/generate_org_ldif.py --out /tmp/workbook-org.ldif
```

---

## Private folders + Filebrowser

On each JuiceFS mount:

```text
<mount>/.meshdrive/users/<username>/private   ← Filebrowser --scope
<mount>/.meshdrive/shares/<share_name>        ← mode 2770, group = share group
```

Symlink shares **into** the private scope so users only open their home in Filebrowser but still see shared folders:

```text
private/shared-<name>  →  ../../shares/<name>
```

APIs: `ensure_bucket_layout()`, `filebrowser_scope_for()`, `set_filebrowser_scope()`.

Cross-drive copy (user A on bucket1 → user B on bucket2): copy files between mounts (or JuiceFS clone); group membership decides who may write into a share — do **not** rely on cross-filesystem symlinks for reliability.

---

## License HTTPS

Control plane: [`authelia-fb-2.0`](../../authelia-fb-2.0/).

Device:

```bash
export MESHDRIVE_LICENSE_STRICT=1
export MESHDRIVE_LICENSE_URL=https://filebrowser.workbook.local/v1/license/validate
meshdrive license activate --token "$TOKEN"
```

---

## MCP buckets (2.1)

`list_storage_backends` / `list_directory` (no path) return **JuiceFS buckets** only — not `etc/`, `var/`, or the whole `/opt/meshdrive` tree. File tools require paths under a configured mount.
