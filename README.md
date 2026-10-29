# circuit-hardening

A Conn3x circuit that tightens SSH and the kernel on a fresh server: a modern set of SSH ciphers and key exchanges, fewer chances to guess, no forwarding, kernel settings that keep one process from reading another's secrets, filesystems and network protocols nobody on a server uses switched off, no core dumps, a tighter umask, and old remote-login daemons removed if they're there.

It takes its picks from [dev-sec's hardening collection](https://github.com/dev-sec/ansible-collection-hardening) (`os_hardening` and `ssh_hardening`), [geerlingguy.security](https://github.com/geerlingguy/ansible-role-security) and [Ansible Lockdown's](https://github.com/ansible-lockdown) CIS roles, keeping the controls that are safe on a host you're about to log in to again, and leaving out the ones those projects themselves mark as likely to break things. Everything has a switch or an override.

This isn't a CIS benchmark, and applying it doesn't make a host CIS or STIG compliant. It's a sensible floor. To measure a host against a benchmark, pair it with [circuit-openscap](https://github.com/conn3xorg/circuit-openscap).

## Usage

```hcl
module "hardening" {
  source = "github.com/conn3xorg/circuit-hardening?ref=v0.1.0"

  hosts                = { web1 = "203.0.113.10", web2 = "203.0.113.11" }
  ssh_private_key_file = "~/.ssh/id_ed25519"
}
```

Then run `conn3x init` and `conn3x apply`. A second `conn3x plan` says `No changes.`, which is also the proof you can still log in: the plan connects with the new SSH settings in place.

Change a single control without restating the rest:

```hcl
  # This host is a bastion: ProxyJump through it needs TCP forwarding.
  sshd_settings = { AllowTcpForwarding = "yes" }

  # Only root may attach a debugger, and leave log_martians alone.
  sysctl = {
    "kernel.yama.ptrace_scope"           = "2"
    "net.ipv4.conf.all.log_martians"     = null
    "net.ipv4.conf.default.log_martians" = null
  }
```

For hosts created in the same plan, pass host objects with the host key you generated, so Conn3x checks it without a known_hosts entry, and each one's distribution in `os`, which picks the sshd service name. Set `os` as well when you put `depends_on` on this module.

```hcl
hosts = {
  for name, d in digitalocean_droplet.web : name => {
    address  = d.ipv4_address
    host_key = tls_private_key.host[name].public_key_openssh
    os       = "ubuntu"
  }
}
```

To try it on a throwaway container first, see [examples/local](examples/local).

### With circuit-baseline

[circuit-baseline](https://github.com/conn3xorg/circuit-baseline) turns off password logins, sets the time zone and chrony, and sets a handful of network sysctls. This circuit doesn't repeat any of that, and the two run side by side on one host:

- Baseline writes `/etc/ssh/sshd_config.d/00-conn3x-baseline.conf` and this circuit writes `01-conn3x-hardening.conf`. sshd keeps the first value it reads, so if you set the same keyword in both, baseline's wins.
- None of this circuit's kernel parameters is in baseline's default `sysctl`. Conn3x keeps each parameter in its own file, `/etc/sysctl.d/90-conn3x-<name>.conf`, so don't set the same parameter in both circuits, or each apply rewrites the other's file.

## What it does

| Control | What it does | Default | Change it with |
| --- | --- | --- | --- |
| SSH key exchange | Removes the NIST curve (`ecdh-sha2-*`), 2048-bit (`diffie-hellman-group14-*`) and SHA-1 exchanges from OpenSSH's own default list. Each host keeps the post-quantum exchanges its OpenSSH has, such as `mlkem768x25519-sha256` from 9.9. | On | `sshd_settings.KexAlgorithms` |
| SSH ciphers | `chacha20-poly1305`, AES-GCM and AES-CTR only. | On | `sshd_settings.Ciphers` |
| SSH MACs | Encrypt-then-MAC with SHA-2 or UMAC-128 only. | On | `sshd_settings.MACs` |
| Group exchange primes | Removes primes under 3072 bits from `/etc/ssh/moduli`. | `3071` | `sshd_moduli_minimum`, `0` to skip |
| Keyboard-interactive login | `KbdInteractiveAuthentication no`, the PAM prompt that can ask for a password even with `PasswordAuthentication no`. The supported distributions' images already turn it off; this keeps it off wherever they don't. | On | `sshd_settings.KbdInteractiveAuthentication` |
| Login attempts | `MaxAuthTries 4`, `LoginGraceTime 30`, `MaxStartups 10:30:60`. | On | `sshd_settings` |
| Idle sessions | `ClientAliveInterval 300` and `ClientAliveCountMax 3` drop a dead connection after 15 minutes. | On | `sshd_settings` |
| Forwarding | `X11Forwarding no`, `AllowAgentForwarding no`, `AllowTcpForwarding no`. | Off | `sshd_settings` |
| SSH logging | `LogLevel VERBOSE`, which logs the fingerprint of the key each login used. | On | `sshd_settings.LogLevel` |
| Kernel pointers and logs | `kernel.kptr_restrict = 2`, `kernel.dmesg_restrict = 1`. | On | `sysctl` |
| ptrace | `kernel.yama.ptrace_scope = 1`: a process can only attach to its own children. | On | `sysctl` |
| ASLR | `kernel.randomize_va_space = 2`, already the default everywhere. Pinned so it stays that way. | On | `sysctl` |
| Line disciplines | `dev.tty.ldisc_autoload = 0`: only root loads TTY line discipline modules. | On | `sysctl` |
| Links, FIFOs and files in sticky directories | `fs.protected_hardlinks`, `fs.protected_symlinks`, `fs.protected_fifos = 1`, `fs.protected_regular = 2`. | On | `sysctl` |
| Reverse path filter | `rp_filter = 2` (loose) on `all` and `default`. | On | `sysctl` |
| Source routing and redirects | Refuses source-routed packets and "secure" redirects, stops sending redirects on new interfaces, and ignores IPv6 redirects. Baseline covers the IPv4 ones it already sets. | On | `sysctl` |
| Martians and bogus ICMP | Logs packets with impossible source addresses, ignores bogus ICMP error responses, and turns on `tcp_rfc1337`. | On | `sysctl` |
| Rare filesystems and protocols | modprobe refuses to load `cramfs`, `freevxfs`, `hfs`, `hfsplus`, `jffs2`, `dccp`, `rds`, `sctp` and `tipc`. | On | `disabled_modules` |
| Core dumps | Hard limit of 0 for every login, `fs.suid_dumpable = 0`, `Storage=none` for systemd-coredump, and on Ubuntu, apport stopped and disabled. | Off | `core_dumps = true` |
| Default umask | `UMASK 027` in `/etc/login.defs`, so new home directories and files aren't readable by everyone. | On | `login_umask`, `null` to skip |
| cron permissions | Takes group and other access off `/etc/crontab` and the `/etc/cron.*` directories that exist. | On | `cron_permissions` |
| Legacy daemons | Removes inetd, xinetd, telnet, rsh, NIS, talk and TFTP servers when installed. | On | `remove_packages` |

On each host, in order: writes `/etc/ssh/sshd_config.d/01-conn3x-hardening.conf`, checks it with `sshd -t`, and reloads sshd (`ssh` on Debian and Ubuntu) only when it changed. A failed check stops the apply before the reload, so the running sshd keeps its old settings. Then it trims the moduli file, stops apport where it runs, sets each kernel parameter in the running kernel and in `/etc/sysctl.d`, installs `kmod` if it's missing and writes `/etc/modprobe.d/conn3x-hardening.conf`, writes `/etc/security/limits.d/90-conn3x-hardening.conf` and `/etc/systemd/coredump.conf.d/conn3x-hardening.conf`, sets `UMASK`, fixes cron's permissions and removes the legacy packages. The limits file sorts after Debian's `10-coredump-debian.conf`, which would otherwise raise the hard limit back to infinity.

The drop-in sorts before the distribution's own, such as Rocky Linux and Fedora's `50-redhat.conf`, so its cipher lists take the place of the system crypto policy's for sshd. The crypto policy still applies to everything else on the host.

Turning a control off leaves the circuit's file with only its header, rather than deleting it. A kernel parameter you take out of the map stays set until the next reboot, and its file stays in `/etc/sysctl.d`.

### What it doesn't do, and why

These are in dev-sec's or the CIS roles' defaults and are left out here because they can break a working server or lock you out:

- **`ip_forward = 0`** would break Docker, Podman, k3s, Tailscale and anything else that routes.
- **`accept_ra = 0` and IPv6 autoconf off** can take away a cloud host's IPv6 address.
- **Strict `rp_filter = 1`** drops traffic on hosts with asymmetric routes, such as multi-homed hosts and Tailscale exit nodes. Loose mode, what Ubuntu and systemd already ship, is kept.
- **`kernel.kexec_load_disabled`** can't be undone without a reboot, and can stop kdump loading its crash kernel at boot.
- **`vfat`, `squashfs` and `udf`** aren't on the module list: `vfat` holds the EFI system partition, `squashfs` holds every snap, and some clouds, Azure among them, hand over provisioning data on a `udf` disc. The circuit won't disable `vfat` or `squashfs`; add `udf` yourself if your cloud doesn't need it.
- **Password ageing** would in time expire the password of an account that only logs in with a key, and PAM then demands a new password at login, which a script or Conn3x can't give.
- **pam_faillock, password quality, cron.allow, auditd, mount options and AIDE** change how people and services work on a host, not just how exposed it is. circuit-openscap's remediation covers them when you're working to a benchmark.

Other caveats:

- `AllowTcpForwarding no` blocks `ssh -J` and `ProxyJump` through this host. Turn it back on for a bastion, including one Conn3x itself jumps through with `jump_hosts`.
- `MaxAuthTries 4` counts each key your SSH agent offers. With more than four keys loaded, point at the right one with `-i` and `IdentitiesOnly yes`.
- On FIPS hosts, `chacha20-poly1305` isn't allowed, so set `Ciphers` to the AES ones.
- `UMASK` in `/etc/login.defs` reaches login shells through pam_umask and new home directories through useradd. A shell that sets its own umask in `/etc/profile` or `/etc/bashrc` overrides it. Files root creates by hand with umask 027 aren't world-readable, which can surprise a web server serving them.
- With ufw, as [circuit-firewall](https://github.com/conn3xorg/circuit-firewall) sets up on Debian and Ubuntu, leave `log_martians` to ufw. ufw sets both `log_martians` keys to 0 from `/etc/ufw/sysctl.conf` each time it starts, so every plan would show a change. Set them to `null` in `sysctl`, as the [Usage](#usage) example does, and set them in that file if you want martians logged.
- On Ubuntu, apport turns `fs.suid_dumpable` back to 2 each time it starts, so with `core_dumps = false` the circuit stops and disables `apport.service`. It doesn't remove the package, since that takes the `ubuntu-server` metapackage with it.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | any | Required | Hosts to configure, by name. Each value is an address, such as `"203.0.113.10"`, or a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file`, `jump_hosts` and `os`, the distribution's ID, such as `ubuntu` or `rocky`, which a host created in the same plan needs. The two forms can be mixed. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |
| `sshd_settings` | map(string) | `{}` | sshd keywords to add or replace, merged over the settings in the table above. A `null` value leaves that keyword out. |
| `sshd_moduli_minimum` | number | `3071` | Remove group exchange primes smaller than this, in the bit size `/etc/ssh/moduli` writes. `0` leaves the file alone. |
| `sysctl` | map(string) | `{}` | Kernel parameters to add or replace, merged over the settings in the table above. A `null` value leaves that parameter out. |
| `disabled_modules` | list(string) | See above | Kernel modules modprobe refuses to load, even as another module's dependency. Can't include `vfat` or `squashfs`. |
| `core_dumps` | bool | `false` | Allow core dumps. |
| `login_umask` | string | `"027"` | `UMASK` in `/etc/login.defs`. `null` leaves the line alone. |
| `cron_permissions` | bool | `true` | Take group and other access off cron's files. |
| `remove_packages` | list(string) | See above | Packages to remove when installed. Names a distribution doesn't have are skipped. |

## Outputs

| Name | Description |
| --- | --- |
| `sshd_file` | Path of the sshd drop-in, `/etc/ssh/sshd_config.d/01-conn3x-hardening.conf`. |
| `sshd_settings` | sshd keywords and values in the drop-in. |
| `sysctl` | Kernel parameters the circuit sets, by name. |

## Requirements

Requires Conn3x v0.6.5 or later, systemd, and an sshd that reads `/etc/ssh/sshd_config.d`, which every supported distribution's does, with a package mirror the host can reach.

## Tested on

Rocky Linux 10, Fedora 45, Ubuntu 24.04 and Debian 13. CI applies [examples/local](examples/local) to each on amd64 in a privileged container, checks that the second plan has no changes, and then checks what sshd will run with through `sshd -T` (ciphers, MACs, no NIST-curve or 2048-bit key exchange, and the login and forwarding settings), that the moduli file has no small primes, that the kernel parameters read back, that `modprobe` refuses `cramfs` through `install /bin/false`, the `UMASK` line, and that a new SSH session gets a hard core limit of 0.

By hand, the circuit ran alongside circuit-baseline on one Debian 13 container, and on an Ubuntu 24.04 droplet (OpenSSH 9.6) and a Rocky Linux 10.2 droplet (OpenSSH 9.9, SELinux enforcing). The same checks passed on both droplets, the second plan had no changes, and both were rebooted and planned again with no changes and the checks passing. Rocky Linux logged no SELinux denials. The Ubuntu reboot is what showed apport resetting `fs.suid_dumpable`, which the circuit now handles.

## License

MPL-2.0. See [LICENSE](LICENSE).
