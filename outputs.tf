output "appliance_front_ip" {
  value       = openstack_networking_port_v2.appliance-front-port.fixed_ip
  description = "Front office IPv4 address"
}

output "appliance_back_ip" {
  value       = openstack_networking_port_v2.appliance-back-port.fixed_ip
  description = "Back office IPv4 address"
}

