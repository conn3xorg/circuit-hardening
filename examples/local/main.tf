variable "port" {
  type    = number
  default = 2222
}

module "hardening" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  # Turn TCP forwarding back on, as a host others jump through needs, and
  # make ptrace admin-only.
  sshd_settings = { AllowTcpForwarding = "yes" }
  sysctl        = { "kernel.yama.ptrace_scope" = "2" }

  disabled_modules = ["cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf", "dccp", "rds", "sctp", "tipc"]
}
