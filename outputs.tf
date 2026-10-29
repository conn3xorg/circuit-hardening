output "sshd_file" {
  description = "Path of the sshd drop-in the circuit writes on each host."
  value       = local.sshd_file
}

output "sshd_settings" {
  description = "sshd keywords and values in the drop-in."
  value       = local.sshd_settings
}

output "sysctl" {
  description = "Kernel parameters the circuit sets, by name."
  value       = local.sysctl
}
