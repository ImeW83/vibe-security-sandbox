#!/bin/sh
set -eu

# Refuse to run as root
if [ "$(id -u)" -eq 0 ]; then
  echo "ERROR: refusing to run as root" >&2
  exit 1
fi

# Refuse to run if the sandbox folder is not writable
if [ ! -w /sandbox ]; then
  echo "ERROR: /sandbox is not writable" >&2
  exit 1
fi

# Keep file permissions tight for anything the agent creates
umask 077

echo "Sandbox ready. Working directory: $(pwd)"

# Hand off to whatever command was passed (defaults to a shell)
if [ "$#" -eq 0 ]; then
  exec /bin/sh
fi
exec "$@"
