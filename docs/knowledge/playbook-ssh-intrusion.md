# Playbook: SSH brute force and credential compromise

Retrieval source for the AI analyst. Sections are split on level-2 headings.

## Triage of SSH brute force
Confirm the source address, the number of failures, the accounts targeted and whether any
attempt succeeded. Many failures across many accounts from one address indicate password
spraying; many failures against one account indicate a targeted brute force. A success from
the same source after failures is the critical signal: treat the account as compromised until
proven otherwise.

## Containment for SSH compromise
Disable password authentication (`PasswordAuthentication no`), require keys, rotate the
affected account's credentials and keys, review `~/.ssh/authorized_keys` for added keys and
terminate active sessions from the source. Block the source at the perimeter if it is not a
legitimate client. Preserve `auth.log` before rotation.

## Scoping after an SSH login
Enumerate everything the account did after the login: processes started (parent `sshd`),
outbound connections, files written under home, cron and systemd changes. Check other hosts for
logins by the same account or from the compromised host (lateral movement).
