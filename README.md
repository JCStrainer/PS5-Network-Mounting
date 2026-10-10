# PS5 Network Mounting

A controller-friendly PS5 homebrew payload for exposing network shares as local filesystem paths, with `/hostapp` as the intended mount target.

## Source roles

- **ps5-ezremote-client** — reference implementation for SMB and FTP protocol handling.
- **Itemzflow** — reference implementation for the PS5 NFS/FUSE mounting flow.
- **libnfs** — NFS client library.
- **fuse-nfs** — FUSE-to-NFS filesystem adapter.
- **ProsperoMgr** — reference for a web-served PS5 payload UI.

## Design

The target is a single PS5 payload/ELF that serves a local web UI over HTTP, reachable from the PS5 browser or another device on the LAN. The UI will provide protocol selection, server/share/export, credentials, mount status, and explicit connect/disconnect actions.

## Important implementation rule

A file-browser connection is not the same as a filesystem mount. The first milestone must prove that NFS can be mounted and accessed at the chosen mountpoint. SMB and FTP are separate milestones and must not be reported as mounted until a filesystem adapter is implemented and verified.

## Current status

Initial project scaffold. No protocol is advertised as working until its native PS5 implementation and build have been verified.
