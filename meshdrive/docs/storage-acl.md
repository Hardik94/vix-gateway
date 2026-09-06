# User ↔ bucket ACL (MeshDrive 2.2)

Many-to-many assignment between **local users** and **JuiceFS storage backends (buckets)**.

## Model

```yaml
# $ROOT/etc/auth.yaml
users:
  alice:
    groups: [user]
    storage_access: [primary, photos]   # bucket names
  bob:
    groups: [user]
    storage_access: [primary]
```

- Creating a bucket does **not** auto-grant users (except optional checks on Add user).
- Deleting a bucket removes its name from every user's `storage_access` and rebuilds portals.
- **Admin** users get Filebrowser scope = global `mnt/` (all buckets). Non-admins get a **portal**.

## Filebrowser portals

```text
$ROOT/var/portals/<username>/
  primary -> $ROOT/mnt/primary
  photos  -> $ROOT/mnt/photos
```

Filebrowser `--scope` = that portal directory. One Filebrowser instance serves everyone.

Also creates `$ROOT/mnt/<bucket>/.meshdrive/users/<user>/private` for future private/share layouts.

## TUI

| Tab | Action |
|-----|--------|
| **Users** | **Assign buckets** — checkboxes for the selected user |
| **Storage** | **Assign users** — checkboxes for the selected bucket |
| **Users → Add user** | Optional bucket checkboxes at create time |

## Agent API

| Method | Path | Body |
|--------|------|------|
| `POST` | `/users` | `storage_access?: string[]` |
| `POST` | `/users/{username}/storage_access` | `{"storage_access":["primary","photos"]}` |
| `GET` | `/storage/{name}/users` | — |
| `POST` | `/storage/{name}/users` | `{"users":["alice","bob"]}` |

Unknown bucket or user names → `400`.

## Edge cases / discrepancies to watch in testing

| Case | Expected |
|------|----------|
| Assign bucket before it exists | Rejected |
| Rename not supported | Bucket name is stable key |
| Admin + empty ACL | Still sees all mounts in FB; ACL list may be empty |
| Non-admin + empty ACL | Empty portal (no bucket symlinks) |
| FB not installed | Auth ACL still saved; scope sync skipped/errors surfaced |
| Delete bucket while assigned | ACL cleaned + portals rebuilt |
| Snap / `$SNAP_COMMON` | Portals under `MESHDRIVE_ROOT/var/portals` |

## Paid / LDAP later

`storage_access` is the device source of truth. On paid upgrade, project to LDAP groups (or Authelia groups) via `authelia-fb-2.0` provision — do not invert so LDAP alone owns bucket ACL on free tier.
