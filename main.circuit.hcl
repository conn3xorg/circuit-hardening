# Facts give each host's family, since Debian and Ubuntu call the sshd
# unit ssh and the Red Hat family calls it sshd.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os     = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }
  debian = { for name, o in local.os : name => contains(["debian", "ubuntu"], o) }

  sshd_file = "/etc/ssh/sshd_config.d/01-conn3x-hardening.conf"

  # KexAlgorithms takes away from OpenSSH's own default rather than naming
  # a list, so a host keeps the post-quantum exchanges its version has
  # (mlkem768x25519-sha256 from 9.9) and an older one doesn't reject names
  # it doesn't know. The Ciphers and MACs named here exist in every
  # OpenSSH the supported distros ship.
  sshd_defaults = {
    KexAlgorithms                = "-ecdh-sha2-*,diffie-hellman-group14-*,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"
    Ciphers                      = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    MACs                         = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
    KbdInteractiveAuthentication = "no"
    MaxAuthTries                 = "4"
    LoginGraceTime               = "30"
    MaxStartups                  = "10:30:60"
    ClientAliveInterval          = "300"
    ClientAliveCountMax          = "3"
    X11Forwarding                = "no"
    AllowAgentForwarding         = "no"
    AllowTcpForwarding           = "no"
    LogLevel                     = "VERBOSE"
  }
  sshd_settings = { for k, v in merge(local.sshd_defaults, var.sshd_settings) : k => v if v != null }

  # None of these overlap circuit-baseline's defaults. The sysctl step
  # writes one file per key, so two circuits setting the same key would
  # take turns rewriting it.
  sysctl_defaults = merge(
    {
      "kernel.kptr_restrict"                       = "2"
      "kernel.dmesg_restrict"                      = "1"
      "kernel.yama.ptrace_scope"                   = "1"
      "kernel.randomize_va_space"                  = "2"
      "dev.tty.ldisc_autoload"                     = "0"
      "fs.protected_hardlinks"                     = "1"
      "fs.protected_symlinks"                      = "1"
      "fs.protected_fifos"                         = "1"
      "fs.protected_regular"                       = "2"
      "net.ipv4.conf.all.rp_filter"                = "2"
      "net.ipv4.conf.default.rp_filter"            = "2"
      "net.ipv4.conf.all.accept_source_route"      = "0"
      "net.ipv4.conf.default.accept_source_route"  = "0"
      "net.ipv6.conf.all.accept_source_route"      = "0"
      "net.ipv6.conf.default.accept_source_route"  = "0"
      "net.ipv4.conf.all.secure_redirects"         = "0"
      "net.ipv4.conf.default.secure_redirects"     = "0"
      "net.ipv4.conf.default.send_redirects"       = "0"
      "net.ipv6.conf.all.accept_redirects"         = "0"
      "net.ipv6.conf.default.accept_redirects"     = "0"
      "net.ipv4.conf.all.log_martians"             = "1"
      "net.ipv4.conf.default.log_martians"         = "1"
      "net.ipv4.icmp_ignore_bogus_error_responses" = "1"
      "net.ipv4.tcp_rfc1337"                       = "1"
    },
    var.core_dumps ? {} : { "fs.suid_dumpable" = "0" },
  )
  sysctl = { for k, v in merge(local.sysctl_defaults, var.sysctl) : k => v if v != null }

  # install ... /bin/false makes modprobe fail outright, which also stops a
  # module being pulled in as a dependency. blacklist alone only stops
  # loading by alias.
  header          = "# Written by Conn3x. Changes here are overwritten on the next apply.\n"
  modprobe_config = join("", [local.header], [for m in var.disabled_modules : "install ${m} /bin/false\nblacklist ${m}\n"])

  cron_paths = "/etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"
}

circuit "hardening" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # sshd uses the first value it reads for each keyword, and the Include
  # sits at the top of sshd_config on every supported distro. 01- sorts
  # after circuit-baseline's 00- drop-in and before the distro's own, such
  # as 50-redhat.conf, which pulls in the crypto policy's cipher lists.
  step "sshd" {
    file {
      path    = local.sshd_file
      content = join("", [local.header], [for k, v in local.sshd_settings : "${k} ${v}\n"])
      mode    = "0600"
    }
  }

  # Check the new settings before the handler reloads sshd, so a bad value
  # fails the apply instead of taking sshd down.
  step "sshd_check" {
    command {
      command  = "/usr/sbin/sshd -t"
      triggers = { sshd = conn3x_file.hardening__sshd[each.key].revision }
    }
    notify = [handler.reload_sshd]
  }

  # Group exchange picks a prime from this file, and the ones under 3072
  # bits are weaker than the rest of the key exchange. sshd reads the file
  # on each connection, so no reload is needed.
  step "moduli" {
    for_each = var.sshd_moduli_minimum > 0 ? { moduli = var.sshd_moduli_minimum } : {}
    command {
      command = "awk '/^#/ || $5 >= ${item.value}' /etc/ssh/moduli > /etc/ssh/moduli.conn3x && cat /etc/ssh/moduli.conn3x > /etc/ssh/moduli && rm /etc/ssh/moduli.conn3x"
      unless  = "! awk '!/^#/ && $5 < ${item.value} { found = 1 } END { exit !found }' /etc/ssh/moduli"
    }
  }

  # Ubuntu's apport sets fs.suid_dumpable back to 2 each time it starts,
  # and pipes crashes to its own handler. Removing the package would take
  # the ubuntu-server metapackage with it, so it's stopped instead. Hosts
  # without apport have nothing to do.
  step "apport" {
    for_each = var.core_dumps ? {} : { apport = "apport.service" }
    command {
      command = "systemctl disable --now ${item.value}"
      unless  = "! systemctl is-enabled -q ${item.value} 2>/dev/null && ! systemctl is-active -q ${item.value}"
    }
  }

  # Minimal images, such as Rocky Linux's container images, ship without it.
  step "sysctl_d" {
    directory {
      path = "/etc/sysctl.d"
    }
  }

  step "sysctl" {
    for_each = local.sysctl
    sysctl {
      name  = item.key
      value = item.value
    }
  }

  # modprobe reads the file; container images can lack it.
  step "kmod" {
    package {
      name = "kmod"
    }
  }

  step "modules" {
    file {
      path    = "/etc/modprobe.d/conn3x-hardening.conf"
      content = local.modprobe_config
    }
  }

  # A setuid program that crashes can leave a core file with secrets from
  # memory in it. The limit covers login sessions through pam_limits, which
  # leaves root out of the * line and keeps the last value it reads for
  # each. 90- sorts after Debian's 10-coredump-debian.conf, which raises the
  # hard limit to infinity. The systemd-coredump setting covers everything
  # else on hosts that use it.
  step "core_limit" {
    file {
      path    = "/etc/security/limits.d/90-conn3x-hardening.conf"
      content = "${local.header}${var.core_dumps ? "" : "* hard core 0\nroot hard core 0\n"}"
    }
  }

  step "coredump" {
    file {
      path    = "/etc/systemd/coredump.conf.d/conn3x-hardening.conf"
      content = "${local.header}${var.core_dumps ? "" : "[Coredump]\nStorage=none\nProcessSizeMax=0\n"}"
    }
  }

  step "umask" {
    for_each = var.login_umask == null ? {} : { umask = var.login_umask }
    line {
      path   = "/etc/login.defs"
      regexp = "^\\s*UMASK\\s"
      line   = "UMASK ${item.value}"
    }
  }

  # Only the paths that exist: Fedora and minimal images don't install cron.
  step "cron" {
    for_each = var.cron_permissions ? { cron = local.cron_paths } : {}
    command {
      command = "find ${item.value} -maxdepth 0 -perm /077 -exec chmod go-rwx {} + 2>/dev/null; true"
      unless  = "test -z \"$(find ${item.value} -maxdepth 0 -perm /077 2>/dev/null)\""
    }
  }

  step "legacy" {
    for_each = toset(var.remove_packages)
    package {
      name  = item.value
      state = "absent"
    }
  }

  handler "reload_sshd" {
    service {
      name   = local.debian[each.key] ? "ssh" : "sshd"
      action = "reload"
    }
  }
}
