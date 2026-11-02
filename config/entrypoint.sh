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

echo "Sandbox ready. Working directory: $(pwd)" >&2

# Interactive shell when no command is given (nothing is packed)
if [ "$#" -eq 0 ]; then
  exec /bin/sh
fi

# Run the command with its stdout sent to stderr, so stdout is free for the output archive
RC=0
"$@" 1>&2 || RC=$?

# Pack /output to stdout; the host unpacks it safely
tar -C /output -cf - . || exit 70

exit "$RC"
