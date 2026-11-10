# Snapshots

Encrypted copies of what the kiwi apps hold, in one folder that a sync client
(Nextcloud) carries to your other devices. Kiwi Proxy snapshots its exits and the
settings of its provider modules; Kiwi Fox (profiles) and Kiwi Custodia (boxes)
use the same folder and the same passphrase through this library.

The apps never sync anything themselves. They write finished, encrypted files into
the folder and read them back; moving the folder between devices is the sync
client's job. Use the apps on one device at a time: a snapshot carries a copy from
one device to the next, it does not merge two copies that were used at once.

## Set up

On the first device:

```bash
kiwi-proxy snapshot setup ~/Nextcloud/kiwi-snapshots
```

Choose a passphrase of at least 12 characters. It is kept in this device's GNOME
keyring; nowhere else. **It cannot be recovered**: without it nothing in the folder
can be read. Then add the folder to your sync client, and take the first
snapshots:

```bash
kiwi-proxy snapshot now
```

On every other device, once the folder has arrived there:

```bash
kiwi-proxy snapshot setup ~/Nextcloud/kiwi-snapshots
kiwi-proxy snapshot list
kiwi-proxy snapshot restore mullvad-se
```

The same is in the app: Preferences (Ctrl+,) → Snapshots → Folder → Choose…. On a
device with no exits yet, "Use a snapshot folder" sits under "Add an exit".

## What is in a snapshot

| Item | What travels | Left out |
| --- | --- | --- |
| Exit | its `exit.json`, the upstream's password, the host listener's password | nothing |
| Module settings | the module's state folder, its podman secrets | what the module calls rebuildable (`snapshot_exclude`) |

A module's settings are, for Mysterium, the keystore, the identity and the
keystore's passphrase; the node's database is left out.

## When snapshots are taken

- After you add or change an exit (window or CLI), and after you configure a
  module, when "Snapshot automatically" is on (the default).
- Whenever you press "Snapshot now" (an exit's menu → Snapshots…) or run
  `kiwi-proxy snapshot now`.

Five are kept per item, ten at most (`kiwi-proxy snapshot set --keep N`). The
oldest goes when a new one is made; the newest of each line never does.

## Which copy is newer

Decided by lineage, never by clocks. Every snapshot names the snapshot the device's
copy came from; every device remembers which snapshot its copy came from and
whether it changed since. So a device can tell:

| State | Meaning |
| --- | --- |
| up to date | this device's copy is the newest snapshot |
| changed since its last snapshot | this device's copy is newer |
| newer snapshot from titan | another device made a newer one from this copy |
| changed here and on titan | both changed since they parted; you choose |
| not on this device | only in the folder; Restore brings it here |

Bringing an exit up when the folder holds a newer copy asks first ("Ask before
using an older copy", on by default): restore and bring up, or bring up as it is.
When both changed, you choose: use the snapshot, or keep this device's copy (it
then becomes the newest, for every device).

**A restore can be undone.** When this device's copy has changes no snapshot holds,
it is snapshotted first ("kept before a restore" in the history), and that one can
be restored like any other.

A restore is refused while the exit is up (take it down first), and when another
exit on this device already has the same name.

## The folder

```
kiwi-snapshots/
  folder.json                   {"format": 1, "kind": "kiwi-snapshots", "id": …}
  check.gpg                     proves a passphrase is the right one
  items/<key>/<id>.meta.gpg     what the snapshot is: name, device, time, lineage
  items/<key>/<id>.snap.gpg     the data
  items/<key>/inuse-<device>.gpg   "in use on lime" (profiles and boxes)
```

- Nothing in a name says what it is. `<key>` is derived from the item under a
  secret that only `check.gpg` holds; `<id>` is random. Kinds, names, devices and
  times are inside the encrypted files.
- Every file is written under a `.part` name and renamed when complete (Nextcloud
  ignores `*.part`), the data before its meta. Files are never changed afterwards:
  new snapshots are new files, old ones are deleted. A sync client has nothing to
  merge and nothing to make conflict copies of; a conflict copy it makes anyway is
  ignored.
- A snapshot whose data has not fully arrived yet shows as "still arriving" and
  cannot be restored until it has.

## Encryption

gpg, symmetric, AES-256, the passphrase stretched with gpg's strongest setting
(iterated and salted SHA-512 at the maximum count). Each gpg call gets a private,
empty home directory that is removed afterwards: your own `~/.gnupg` is never
touched, and no gpg-agent keeps the passphrase. The passphrase reaches gpg through
a pipe, never on a command line or in the environment.

You can open a snapshot without any kiwi app:

```bash
gpg -d FILE.snap.gpg | zstd -d | tar -x
```

(`kiwi-proxy snapshot history NAME` says which file is which; the meta files are
JSON, `gpg -d FILE.meta.gpg`.)

On a machine without a Secret Service (a server over SSH) the passphrase is kept
the way kiwi-proxy keeps every other password there: a 0600 file under
`~/.config/kiwi-proxy/secrets`. `kiwi-proxy snapshot lock` forgets it on this
device; `unlock` asks again.

## Commands

```
kiwi-proxy snapshot setup FOLDER [--device NAME]   make or join the folder
kiwi-proxy snapshot status                         folder, device, locked or not
kiwi-proxy snapshot unlock | lock                  enter or forget the passphrase here
kiwi-proxy snapshot set [--keep N] [--automatic on|off] [--ask-older on|off] [--device NAME]
kiwi-proxy snapshot list                           everything in the folder, and its state here
kiwi-proxy snapshot now [EXIT | module:NAME ...]   snapshot now (default: all)
kiwi-proxy snapshot history EXIT | module:NAME     the snapshots of one item
kiwi-proxy snapshot restore EXIT | module:NAME [--id ID] [--yes]
kiwi-proxy snapshot forget EXIT | module:NAME --yes   delete its snapshots from the folder
```

`--passphrase-stdin` reads the passphrase from standard input (scripts);
`--no-remember` uses it for this command only.

## For the other apps

`kiwi_proxy.snapshots` is the library: `take(kind, item, name, fill)`,
`relation(kind, item, here=…)`, `restore(kind, item, id, apply, here=…,
keep_current=…)`, `mark_changed`, `mark_in_use` / `in_use_elsewhere`, and the
screens in `kiwi_proxy.ui.snapshots` (the Snapshots preferences page, the unlock
prompt, the history dialog, the "newer copy" prompt). The kinds are `exit`,
`module`, `profile` and `box`.
