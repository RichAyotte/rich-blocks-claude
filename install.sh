#!/bin/sh
set -eu

repo="RichAyotte/rich-blocks-claude"
name="rich-blocks-claude"
install_dir="${INSTALL_DIR:-$HOME/.local/bin}"

arch=$(uname -m)
case "$arch" in
x86_64) suffix="linux-x86_64" ;;
aarch64) suffix="linux-aarch64" ;;
*)
	printf "Unsupported architecture: %s\n" "$arch" >&2
	exit 1
	;;
esac

mkdir -p "$install_dir"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

printf "Downloading %s for %s...\n" "$name" "$arch"
curl -fsSL "https://github.com/${repo}/releases/latest/download/${name}-${suffix}.tar.xz" |
	tar xJ -C "$tmpdir"

install -m 755 "$tmpdir/${name}-${suffix}/${name}" "$install_dir/"

printf "Installed %s to %s/%s\n" "$name" "$install_dir" "$name"

case ":$PATH:" in
*":${install_dir}:"*) ;;
*) printf "Warning: %s is not in your PATH\n" "$install_dir" >&2 ;;
esac

# Check optional dependencies
printf "\nChecking dependencies...\n"
missing=0
for dep in shellcheck shfmt rg fd; do
	if ! command -v "$dep" >/dev/null 2>&1; then
		printf "  Warning: %s not found\n" "$dep" >&2
		missing=1
	fi
done
if [ "$missing" -eq 0 ]; then
	printf "  All dependencies found.\n"
fi

# Register plugin with Claude Code
printf "\nRegistering plugin...\n"
if command -v claude >/dev/null 2>&1; then
	unset CLAUDECODE
	case "$(claude plugin marketplace list --json 2>/dev/null)" in
	*rich-plugins*)
		printf "  Marketplace 'rich-plugins' already registered, skipping.\n"
		;;
	*)
		claude plugin marketplace add RichAyotte/claude-plugins
		;;
	esac
	claude plugin install rich-blocks-claude@rich-plugins --scope user
	printf "  Plugin registered and installed.\n"
else
	printf "  claude CLI not found. Run these commands manually:\n" >&2
	printf "    claude plugin marketplace add RichAyotte/claude-plugins\n" >&2
	printf "    claude plugin install rich-blocks-claude@rich-plugins --scope user\n" >&2
fi
