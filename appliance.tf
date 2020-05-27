################################################################################
# Instances
#
resource "openstack_compute_instance_v2" "appliance" {
  name      = "management"
  image_id  = var.image_id
  flavor_id = var.flavor_id

  network {
    port = openstack_networking_port_v2.appliance-front-port.id
  }

  user_data = templatefile(
    "${path.module}/cloud-init.sh",
    {
      internet_http_proxy_url = var.internet_http_proxy_url,
      internet_http_no_proxy  = var.internet_http_no_proxy,
      static_hosts            = var.static_hosts,

      os_auth_url    = var.os_auth_url,
      os_username    = var.os_username,
      os_password    = var.os_password,
      os_region_name = var.os_region_name,

      #metrics_endpoint_url = var.metrics_endpoint_url,
      #influxdb_token       = var.influxdb_token,
      #influxdb_bucket      = var.influxdb_bucket,
      #influxdb_org         = var.influxdb_org,

      #logs_endpoint_url = var.logs_endpoint_url,

      consul_dns_domain = var.consul_dns_domain,
      consul_datacenter = var.consul_datacenter,
      consul_encrypt    = var.consul_encrypt,
      consul_dns_server = var.consul_dns_server,

      ntp_server = var.ntp_server,

      git_repo_checkout = var.git_repo_checkout,
      git_repo_username = var.git_repo_username,
      git_repo_password = var.git_repo_password,

      git_repo_url = var.git_repo_url,

      backoffice_ip_address = openstack_networking_port_v2.appliance-back-port.all_fixed_ips[0]
    }
  )
}

################################################################################
# Security groups
# See: https://github.com/hashicorp/terraform-aws-consul/blob/master/modules/consul-security-group-rules/main.tf
#
resource "openstack_networking_secgroup_v2" "appliance-secgroup" {
  name        = "appliance-secgroup"
  description = "Hashicorp services"
}

resource "openstack_networking_secgroup_rule_v2" "appliance_nomad_secgroup_jobs_tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 20000
  port_range_max    = 32000
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_nomad_secgroup_jobs_udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 20000
  port_range_max    = 32000
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_nomad_allow_http_inbound" {
  direction      = "ingress"
  port_range_min = var.nomad_http_port
  port_range_max = var.nomad_http_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_nomad_allow_rpc_inbound" {
  direction      = "ingress"
  port_range_min = var.nomad_rpc_port
  port_range_max = var.nomad_rpc_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_nomad_allow_serf_tcp_inbound" {
  direction      = "ingress"
  port_range_min = var.nomad_serf_port
  port_range_max = var.nomad_serf_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_nomad_allow_serf_udp_inbound" {
  direction      = "ingress"
  port_range_min = var.nomad_serf_port
  port_range_max = var.nomad_serf_port
  protocol       = "udp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_server_rpc_inbound" {
  ethertype      = "IPv4"
  direction      = "ingress"
  port_range_min = var.consul_server_rpc_port
  port_range_max = var.consul_server_rpc_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_cli_rpc_inbound" {
  ethertype      = "IPv4"
  direction      = "ingress"
  port_range_min = var.consul_cli_rpc_port
  port_range_max = var.consul_cli_rpc_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_serf_wan_tcp_inbound" {
  ethertype      = "IPv4"
  direction      = "ingress"
  port_range_min = var.consul_serf_wan_port
  port_range_max = var.consul_serf_wan_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_serf_wan_udp_inbound" {
  ethertype      = "IPv4"
  direction      = "ingress"
  port_range_min = var.consul_serf_wan_port
  port_range_max = var.consul_serf_wan_port
  protocol       = "udp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_http_api_inbound" {
  ethertype      = "IPv4"
  direction      = "ingress"
  port_range_min = var.consul_http_api_port
  port_range_max = var.consul_http_api_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_dns_tcp_inbound" {
  ethertype      = "IPv4"
  direction      = "ingress"
  port_range_min = var.consul_dns_port
  port_range_max = var.consul_dns_port
  protocol       = "tcp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_dns_udp_inbound" {
  ethertype      = "IPv4"
  direction      = "ingress"
  port_range_min = var.consul_dns_port
  port_range_max = var.consul_dns_port
  protocol       = "udp"

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_server_rpc_inbound_from_security_group_ids" {
  count           = var.consul_allowed_inbound_security_group_count
  ethertype       = "IPv4"
  direction       = "ingress"
  port_range_min  = var.consul_server_rpc_port
  port_range_max  = var.consul_server_rpc_port
  protocol        = "tcp"
  remote_group_id = element(var.allowed_inbound_security_group_ids, count.index)

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_cli_rpc_inbound_from_security_group_ids" {
  count           = var.consul_allowed_inbound_security_group_count
  ethertype       = "IPv4"
  direction       = "ingress"
  port_range_min  = var.consul_cli_rpc_port
  port_range_max  = var.consul_cli_rpc_port
  protocol        = "tcp"
  remote_group_id = element(var.allowed_inbound_security_group_ids, count.index)

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_serf_wan_tcp_inbound_from_security_group_ids" {
  count           = var.consul_allowed_inbound_security_group_count
  ethertype       = "IPv4"
  direction       = "ingress"
  port_range_min  = var.consul_serf_wan_port
  port_range_max  = var.consul_serf_wan_port
  protocol        = "tcp"
  remote_group_id = element(var.allowed_inbound_security_group_ids, count.index)

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_serf_wan_udp_inbound_from_security_group_ids" {
  count           = var.consul_allowed_inbound_security_group_count
  ethertype       = "IPv4"
  direction       = "ingress"
  port_range_min  = var.consul_serf_wan_port
  port_range_max  = var.consul_serf_wan_port
  protocol        = "udp"
  remote_group_id = element(var.allowed_inbound_security_group_ids, count.index)

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_http_api_inbound_from_security_group_ids" {
  count           = var.consul_allowed_inbound_security_group_count
  ethertype       = "IPv4"
  direction       = "ingress"
  port_range_min  = var.consul_http_api_port
  port_range_max  = var.consul_http_api_port
  protocol        = "tcp"
  remote_group_id = element(var.allowed_inbound_security_group_ids, count.index)

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_dns_tcp_inbound_from_security_group_ids" {
  count           = var.consul_allowed_inbound_security_group_count
  ethertype       = "IPv4"
  direction       = "ingress"
  port_range_min  = var.consul_dns_port
  port_range_max  = var.consul_dns_port
  protocol        = "tcp"
  remote_group_id = element(var.allowed_inbound_security_group_ids, count.index)

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

resource "openstack_networking_secgroup_rule_v2" "appliance_consul_allow_dns_udp_inbound_from_security_group_ids" {
  count           = var.consul_allowed_inbound_security_group_count
  ethertype       = "IPv4"
  direction       = "ingress"
  port_range_min  = var.consul_dns_port
  port_range_max  = var.consul_dns_port
  protocol        = "udp"
  remote_group_id = element(var.allowed_inbound_security_group_ids, count.index)

  security_group_id = openstack_networking_secgroup_v2.appliance-secgroup.id
}

