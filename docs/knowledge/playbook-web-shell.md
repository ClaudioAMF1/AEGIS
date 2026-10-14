# Playbook: Web shells and cryptomining

## Web server spawning shells
A shell whose parent is nginx, apache, php-fpm or an application runtime usually means command
injection or a web shell. Review the web access logs around the process start, identify the
requested script, and look for recently modified files in the web root.

## Cryptocurrency miners
Command lines containing `stratum+tcp`, `--donate-level` or binaries named like xmrig indicate
mining. Expect sustained CPU usage and connections to pool ports (3333, 5555, 14444). Remove the
binary, kill the process tree, find the persistence mechanism and the initial access vector.
