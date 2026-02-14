# rich-blocks-claude

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Safety and productivity hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## What it does

A hook system that intercepts Claude Code's `PreToolUse`, `PostToolUse`, and `Notification` events to enforce safe coding practices, block dangerous operations, and provide desktop integration. Written in Rust for minimal latency on every tool call.

## Features

- **Dangerous command blocking** &mdash; prevents `sudo`, destructive `rm`, `chmod 777`, `dd` to block devices, `mkfs`/`wipefs`, fork bombs, and more
- **Tool enforcement** &mdash; blocks `grep`/`find`/`cat` and suggests `rg`/`fd`/dedicated tools; blocks hardcoded `/tmp` paths (use `mktemp`); blocks useless `cat` patterns
- **Sensitive file protection** &mdash; guards SSH keys, cloud credentials, `.env` files, GPG keyrings, shell history, password databases, and more across Read/Write/Edit/Grep/Bash tools
- **Python prevention** &mdash; blocks `.py` file creation and inline `python` usage
- **Desktop notifications** &mdash; Hyprland-aware notifications via `notify-send` when Claude finishes work in an unfocused window
- **Shell syntax checking** &mdash; validates commands with `bash -n`, `shellcheck`, and `shfmt` before execution
- **File operation sandboxing** &mdash; restricts `rm`/`mv`/`cp` to project directories, `~/.claude/`, and `/tmp/`
- **Cargo auto-approval** &mdash; allows `cargo` commands to proceed without prompting

## Requirements

- Rust 1.87.0+ (2024 edition)
- [shellcheck](https://www.shellcheck.net/)
- [shfmt](https://github.com/mvdan/sh)
- [rg](https://github.com/BurntSushi/ripgrep) (ripgrep)
- [fd](https://github.com/sharkdp/fd)

**Optional** (Hyprland-only):

- `hyprctl` and `notify-send` &mdash; desktop notifications when Claude finishes work in an unfocused window. Requires [Hyprland](https://hyprland.org/) for window-focus detection.

## Installation

**Install script** (recommended) &mdash; auto-detects architecture and installs to `~/.local/bin`:

```sh
curl -fsSL https://raw.githubusercontent.com/RichAyotte/rich-blocks-claude/main/install.sh | sh
```

Set `INSTALL_DIR` to change the install location:

```sh
curl -fsSL https://raw.githubusercontent.com/RichAyotte/rich-blocks-claude/main/install.sh | INSTALL_DIR=/usr/local/bin sh
```

**Build from source:**

```sh
cargo install --git https://github.com/RichAyotte/rich-blocks-claude
```

Then register the plugin manually:

```sh
claude plugin marketplace add RichAyotte/claude-plugins
claude plugin install rich-blocks-claude@rich-plugins --scope user
```

The install script handles this automatically; these commands are only needed for build-from-source installs.

### Settings file

Behavior can be customized via `~/.config/rich-blocks-claude/settings.json` (or `$XDG_CONFIG_HOME/rich-blocks-claude/settings.json`). All fields are optional &mdash; missing fields use defaults, and a missing or malformed file uses all defaults.

```json
{
  "notify_cmd": "notify-send",
  "file_ops_allowed": ["$HOME/.claude/", "/tmp/", "./src/", "./tests/", "./target/", "./docs/"],
  "shellcheck_exclude": "SC1091,SC2086,SC2046,SC2035",
  "auto_approve_prefixes": ["cargo clippy", "cargo check", "cargo fmt", "cargo test", "cargo build", "cargo run", "cargo doc", "cargo clean", "cargo update", "cargo tree", "cargo metadata"]
}
```

| Field | Default | Description |
|---|---|---|
| `notify_cmd` | `"notify-send"` | Command used for desktop notifications. Set to `""` to disable. |
| `file_ops_allowed` | *(see above)* | Paths where `rm`/`mv`/`cp` are permitted. `$HOME` is expanded. |
| `shellcheck_exclude` | `"SC1091,SC2086,SC2046,SC2035"` | Comma-separated shellcheck error codes to suppress. |
| `auto_approve_prefixes` | *(see above)* | Commands matching these prefixes skip the permission prompt. |
