## Copyright (c) 2020, Oracle and/or its affiliates.
## All rights reserved. The Universal Permissive License (UPL), Version 1.0 as shown at http://oss.oracle.com/licenses/upl

package oci.tf_analysis

#----------------------------
# project-specific variables
#----------------------------
# the IP address space that's assigned to this environment
subnet_allowed_cidrs = [
  "192.168.0.0/23",
  "192.168.1.0/29"
]
# the types of resources allowed (or prohibited)
allowed_resource_types = [
  "oci_core_subnet",
  "oci_core_security_list",
  "oci_core_dhcp_options",
  "oci_core_route_table",
  "oci_core_instance",
  "oci_database_db_system"
]
blacklisted_resource_types = [
  "oci_core_vcn",
  "oci_core_internet_gateway",
  "oci_core_drg",
  "oci_core_local_peering_gateway",
  "oci_identity_compartment"
]
# the OCIDs of VCNs that are allowed to be used by this environment
allowed_vcn_ids = [
  "ocid1.vcn.oc1.phx.abc123"
]
# specify the compartment OCIDs that can be used by resources in this environment
allowed_compartment_ids = [
  "ocid1.compartment.oc1..abc123"
]
# provide the OCIDs of allowed Route Target IDs (gateways, private IPs, etc)
allowed_route_target_ids = [
  "ocid1.natgateway.oc1.phx.abc123",
  "ocid1.servicegateway.oc1.phx.abc123"
]

# permitted Security List rules
allowed_ingress_rules := [
  # all
  { "protocol": "all", "cidr": "10.1.2.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  # udp
  { "protocol": "17", "cidr": "10.0.0.0/28", "src_port_min": null, "src_port_max": null, "dst_port_min": 123, "dst_port_max": 123, "icmp_type": null, "icmp_code": null },
  # tcp
  { "protocol": "6", "cidr": "10.0.0.1/32", "src_port_min": null, "src_port_max": null, "dst_port_min": 443, "dst_port_max": 443, "icmp_type": null, "icmp_code": null },
]

allowed_egress_rules := [
  # all
  { "protocol": "all", "cidr": "10.0.0.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  { "protocol": "all", "cidr": "10.0.99.2/32", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  # other
  { "protocol": "45", "cidr": "10.0.99.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  # udp
  { "protocol": "17", "cidr": "10.0.1.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": 123, "dst_port_max": 123, "icmp_type": null, "icmp_code": null },
  { "protocol": "17", "cidr": "10.0.0.2/32", "src_port_min": null, "src_port_max": null, "dst_port_min": 123, "dst_port_max": 123, "icmp_type": null, "icmp_code": null },
  { "protocol": "17", "cidr": "10.0.2.0/24", "src_port_min": 123, "src_port_max": 123, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  { "protocol": "17", "cidr": "10.0.2.1/32", "src_port_min": 123, "src_port_max": 123, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  { "protocol": "17", "cidr": "10.0.3.0/24", "src_port_min": 123, "src_port_max": 123, "dst_port_min": 123, "dst_port_max": 123, "icmp_type": null, "icmp_code": null },
  { "protocol": "17", "cidr": "10.0.4.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  # tcp
  { "protocol": "6", "cidr": "10.0.1.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": 443, "dst_port_max": 443, "icmp_type": null, "icmp_code": null },
  { "protocol": "6", "cidr": "10.0.2.0/24", "src_port_min": 443, "src_port_max": 443, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  { "protocol": "6", "cidr": "10.0.3.0/24", "src_port_min": 443, "src_port_max": 443, "dst_port_min": 443, "dst_port_max": 443, "icmp_type": null, "icmp_code": null },
  { "protocol": "6", "cidr": "10.0.4.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  # icmp
  { "protocol": "1", "cidr": "10.0.5.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": null, "icmp_code": null },
  { "protocol": "1", "cidr": "10.0.6.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": 8, "icmp_code": null },
  { "protocol": "1", "cidr": "10.0.7.0/24", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": 3, "icmp_code": 4 },
  { "protocol": "1", "cidr": "10.0.6.2/32", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": 8, "icmp_code": 1 },
  { "protocol": "1", "cidr": "10.0.7.2/32", "src_port_min": null, "src_port_max": null, "dst_port_min": null, "dst_port_max": null, "icmp_type": 3, "icmp_code": 8 },
]