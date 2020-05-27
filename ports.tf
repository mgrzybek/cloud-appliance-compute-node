################################################################################
# Ports
#
resource "openstack_networking_port_v2" "appliance-front-port" {
  name = "appliance-front-port"
  security_group_ids = [
    var.default_secgroup_id
  ]
  network_id = var.front_net_id
}

resource "openstack_networking_port_v2" "appliance-back-port" {
  name = "appliance-back-port"
  security_group_ids = [
    var.default_secgroup_id,
    openstack_networking_secgroup_v2.appliance-secgroup.id
  ]
  network_id = var.back_net_id
}

resource "openstack_compute_interface_attach_v2" "appliance-back-port" {
  instance_id = openstack_compute_instance_v2.appliance.id
  port_id     = openstack_networking_port_v2.appliance-back-port.id
}

