variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file, jump_hosts or os."

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "almalinux", "rhel", "centos", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky, almalinux, rhel, centos or fedora."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}
variable "sshd_settings" {
  type        = map(string)
  default     = {}
  description = "sshd keywords to add to the built-in settings or replace them, such as { AllowTcpForwarding = \"yes\" }. A null value leaves that keyword out of the drop-in."

  validation {
    condition     = alltrue([for k, v in var.sshd_settings : can(regex("^[A-Za-z]+$", k)) && (v == null || !strcontains(coalesce(v, "-"), "\n"))])
    error_message = "sshd_settings keys are sshd keywords, such as MaxAuthTries, and values are a single line."
  }
}

variable "sshd_moduli_minimum" {
  type        = number
  default     = 3071
  description = "Remove Diffie-Hellman group exchange primes smaller than this many bits from /etc/ssh/moduli. 0 leaves the file alone."

  validation {
    condition     = var.sshd_moduli_minimum == 0 || (var.sshd_moduli_minimum >= 2047 && var.sshd_moduli_minimum <= 8191)
    error_message = "sshd_moduli_minimum is 0, or a bit size from 2047 to 8191 as the moduli file writes it."
  }
}

variable "sysctl" {
  type        = map(string)
  default     = {}
  description = "Kernel parameters to add to the built-in settings or replace them, by name. A null value leaves that parameter out."

  validation {
    condition     = alltrue([for k in keys(var.sysctl) : can(regex("^[a-z0-9_.*/-]+$", k))])
    error_message = "sysctl keys are kernel parameter names, such as kernel.kptr_restrict."
  }
}

variable "disabled_modules" {
  type        = list(string)
  default     = ["cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "dccp", "rds", "sctp", "tipc"]
  description = "Kernel modules modprobe refuses to load. An empty list leaves the circuit's modprobe file with only its header."

  validation {
    condition     = alltrue([for m in var.disabled_modules : can(regex("^[a-zA-Z0-9_-]+$", m))])
    error_message = "disabled_modules are module names, such as cramfs."
  }

  # vfat holds the EFI system partition, and squashfs holds every snap.
  validation {
    condition     = length(setintersection(var.disabled_modules, ["vfat", "squashfs"])) == 0
    error_message = "Disabling vfat or squashfs can leave a host unable to boot or run snaps, so the circuit won't do it."
  }
}

variable "core_dumps" {
  type        = bool
  default     = false
  description = "Allow core dumps. When false, the circuit turns them off for login sessions, setuid programs and systemd-coredump."
}

variable "login_umask" {
  type        = string
  default     = "027"
  description = "UMASK in /etc/login.defs, which pam_umask and useradd read. null leaves the line alone."

  validation {
    condition     = var.login_umask == null || can(regex("^0?[0-7]{3}$", coalesce(var.login_umask, "-")))
    error_message = "login_umask is an octal umask, such as \"027\"."
  }
}

variable "cron_permissions" {
  type        = bool
  default     = true
  description = "Take group and other access off /etc/crontab and the /etc/cron.* directories that exist."
}

variable "remove_packages" {
  type        = list(string)
  default     = ["xinetd", "openbsd-inetd", "inetutils-inetd", "telnetd", "inetutils-telnetd", "telnet-server", "rsh-server", "rsh-redone-server", "ypserv", "nis", "talkd", "tftp-server", "tftpd-hpa"]
  description = "Packages to remove when installed. Names a distribution doesn't have are skipped."
}
