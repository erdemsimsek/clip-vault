# ClipVault

An encrypted clipboard manager for Linux (Wayland) and macOS that doesn't keep your secrets forever.

> [!WARNING]
> **Pre-alpha** — under active development, nothing usable yet.

[![CI](https://github.com/erdemsimsek/clip-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/erdemsimsek/clip-vault/actions/workflows/ci.yml)

## Why ClipVault?

Clipboard managers keep a copy of everything you've ever copied. That's useful when you need to paste something from earlier, but it's a problem when the history includes passwords, API tokens, or SSH keys. On most managers these sit on disk in plain text for as long as the manager has been running.

ClipVault aims to fix that. The history is encrypted on disk. Anything that looks like a secret — passwords, tokens, keys, or content that an app marks as a secret — gets a short expiry time and is wiped automatically.

## Goals

- Encrypt the clipboard history on disk
- Detect passwords, tokens and keys, and delete them after a short time
- **Linux:** work as a drop-in replacement for `cliphist`, so existing Sway setups keep working
- **macOS:** be an alternative to Maccy for people who want their history encrypted and their secrets gone automatically
- Keep everything local — no telemetry, no cloud
- Plan for syncing across devices later
- Open source under MIT

## Roadmap

- [ ] **Milestone 1** — Core library, daemon, command-line tool
- [ ] **Milestone 2** — Desktop integration (Sway and a systemd unit on Linux; pasteboard watcher and a launchd agent on macOS), deduplication
- [ ] **Milestone 3** — Terminal UI picker with fuzzy search
- [ ] **Milestone 4** — Image clipboard, AUR package, fish completions
- [ ] **Phase 2** — Encrypted sync across devices
- [ ] **Phase 3** — Android client

See the [open issues](https://github.com/erdemsimsek/clip-vault/issues) for current work.

## Contributing

ClipVault is in early development. Contribution guidelines will be added in `CONTRIBUTING.md` once Milestone 1 lands. In the meantime, issues and feature ideas are welcome.

## Licence

Licensed under the [MIT Licence](LICENSE).
