## Copyright (c) 2020, Oracle and/or its affiliates.
## All rights reserved. The Universal Permissive License (UPL), Version 1.0 as shown at http://oss.oracle.com/licenses/upl

package oci.tf_analysis

invalid_tfplan := {
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "oci_identity_compartment.Internal",
          "mode": "managed",
          "type": "oci_identity_compartment",
          "name": "Internal",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.tenancy.oc1..abc123",
            "description": "Another test, you know!",
            "enable_delete": null,
            "name": "Internal",
            "timeouts": null
          }
        },
        {
          "address": "oci_core_internet_gateway.IGW1",
          "mode": "managed",
          "type": "oci_core_internet_gateway",
          "name": "IGW1",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "display_name": "IGW1",
            "enabled": true,
            "timeouts": null
          }
        },
        {
          "address": "oci_core_dhcp_options.test_dhcp",
          "mode": "managed",
          "type": "oci_core_dhcp_options",
          "name": "test_dhcp",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..123",
            "display_name": "test_dhcp",
            "options": [
              {
                "custom_dns_servers": [],
                "server_type": "VcnLocalPlusInternet",
                "type": "DomainNameServer"
              },
              {
                "custom_dns_servers": [],
                "search_domain_names": [
                  "test.oraclecloud.local"
                ],
                "type": "SearchDomain"
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.123"
          }
        },
        {
          "address": "oci_core_instance.AppServer1",
          "mode": "managed",
          "type": "oci_core_instance",
          "name": "AppServer1",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:US-ASHBURN-AD-1",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "create_vnic_details": [
              {
                "assign_public_ip": "false",
                "nsg_ids": null,
                "skip_source_dest_check": false
              }
            ],
            "display_name": "AppServer1",
            "extended_metadata": null,
            "hostname_label": "appserver1",
            "metadata": {
              "ssh_authorized_keys": "blah-blah-blah"
            },
            "preserve_boot_volume": null,
            "shape": "VM.Standard1.1",
            "source_details": [
              {
                "source_id": "ocid1.image.oc1.eu-frankfurt-1.abc123",
                "source_type": "image"
              }
            ],
            "timeouts": null
          }
        },
        {
          "address": "oci_core_instance.Test123",
          "mode": "managed",
          "type": "oci_core_instance",
          "name": "Test123",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:US-ASHBURN-AD-1",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "create_vnic_details": [
              {
                "assign_public_ip": "true",
                "nsg_ids": null,
                "skip_source_dest_check": false
              }
            ],
            "display_name": "Test123",
            "extended_metadata": null,
            "hostname_label": "test123",
            "metadata": {
              "ssh_authorized_keys": "blah-blah-blah"
            },
            "preserve_boot_volume": null,
            "shape": "VM.Standard1.1",
            "source_details": [
              {
                "source_id": "ocid1.image.oc1.eu-frankfurt-1.abc123",
                "source_type": "image"
              }
            ],
            "timeouts": null
          }
        },
        {
          "address": "oci_core_route_table.Test_Route_1",
          "mode": "managed",
          "type": "oci_core_route_table",
          "name": "Test_Route_1",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "Test_Route_1",
            "route_rules": [
              {
                "destination": "0.0.0.0/0",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.internetgateway.oc1.phx.abc123"
              },
              {
                "destination": "1.1.1.0/24",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.servicegateway.oc1.phx.abc123"
              },
              {
                "destination": "10.1.1.0/24",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.natgateway.oc1.phx.abc123"
              },
              {
                "destination": "192.168.0.0/16",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.localpeeringgateway.oc1.phx.abc123"
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_security_list.test_acl",
          "mode": "managed",
          "type": "oci_core_security_list",
          "name": "test_acl",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_acl",
            "egress_security_rules": [
              {
                "destination": "0.0.0.0/0",
                "destination_type": "CIDR_BLOCK",
                "icmp_options": [],
                "protocol": "all",
                "stateless": true,
                "tcp_options": [],
                "udp_options": []
              },
              {
                "destination": "123.0.0.0/16",
                "destination_type": "CIDR_BLOCK",
                "icmp_options": [
                  {
                    "code": 3,
                    "type": 4
                  }
                ],
                "protocol": "1",
                "stateless": false,
                "tcp_options": [],
                "udp_options": []
              },
              {
                "destination": "192.168.0.0/16",
                "destination_type": "CIDR_BLOCK",
                "icmp_options": [],
                "protocol": "17",
                "stateless": true,
                "tcp_options": [],
                "udp_options": [
                  {
                    "max": 1230,
                    "min": 789,
                    "source_port_range": [
                      {
                        "max": 456,
                        "min": 123
                      }
                    ]
                  }
                ]
              }
            ],
            "ingress_security_rules": [
              {
                "icmp_options": [],
                "protocol": "1",
                "source": "123.199.123.0/24",
                "source_type": "CIDR_BLOCK",
                "stateless": false,
                "tcp_options": [],
                "udp_options": []
              },
              {
                "icmp_options": [],
                "protocol": "6",
                "source": "123.199.123.0/24",
                "source_type": "CIDR_BLOCK",
                "stateless": false,
                "tcp_options": [
                  {
                    "max": 80,
                    "min": 80,
                    "source_port_range": []
                  }
                ],
                "udp_options": []
              },
              {
                "icmp_options": [],
                "protocol": "all",
                "source": "10.0.0.0/24",
                "source_type": "CIDR_BLOCK",
                "stateless": false,
                "tcp_options": [],
                "udp_options": []
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_security_list.testing-2",
          "mode": "managed",
          "type": "oci_core_security_list",
          "name": "testing-2",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "testing #2",
            "egress_security_rules": [],
            "ingress_security_rules": [
              {
                "icmp_options": [],
                "protocol": "6",
                "source": "0.0.0.0/0",
                "source_type": "CIDR_BLOCK",
                "stateless": false,
                "tcp_options": [
                  {
                    "max": 22,
                    "min": 22,
                    "source_port_range": []
                  }
                ],
                "udp_options": []
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_subnet.test_subnet_1",
          "mode": "managed",
          "type": "oci_core_subnet",
          "name": "test_subnet_1",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:PHX-AD-1",
            "cidr_block": "10.0.0.0/24",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_subnet_1",
            "dns_label": "testsubnet1",
            "prohibit_public_ip_on_vnic": false,
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_subnet.test_subnet_2",
          "mode": "managed",
          "type": "oci_core_subnet",
          "name": "test_subnet_2",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:PHX-AD-1",
            "cidr_block": "10.0.1.0/24",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_subnet_2",
            "dns_label": "testsubnet2",
            "prohibit_public_ip_on_vnic": false,
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_subnet.test_subnet_3",
          "mode": "managed",
          "type": "oci_core_subnet",
          "name": "test_subnet_3",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:PHX-AD-1",
            "cidr_block": "10.0.2.0/24",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_subnet_3",
            "dns_label": "testsubnet3",
            "prohibit_public_ip_on_vnic": false,
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        }
      ]
    }
  }
}
valid_tfplan := {
"planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "oci_core_dhcp_options.test_dhcp",
          "mode": "managed",
          "type": "oci_core_dhcp_options",
          "name": "test_dhcp",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_dhcp",
            "options": [
              {
                "custom_dns_servers": [],
                "server_type": "VcnLocalPlusInternet",
                "type": "DomainNameServer"
              },
              {
                "custom_dns_servers": [],
                "search_domain_names": [
                  "test.oraclecloud.local"
                ],
                "type": "SearchDomain"
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_instance.AppServer1",
          "mode": "managed",
          "type": "oci_core_instance",
          "name": "AppServer1",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:US-ASHBURN-AD-1",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "create_vnic_details": [
              {
                "assign_public_ip": "false",
                "nsg_ids": null,
                "skip_source_dest_check": false
              }
            ],
            "display_name": "AppServer1",
            "extended_metadata": null,
            "hostname_label": "appserver1",
            "metadata": {
              "ssh_authorized_keys": "blah-blah-blah"
            },
            "preserve_boot_volume": null,
            "shape": "VM.Standard1.1",
            "source_details": [
              {
                "source_id": "ocid1.image.oc1.eu-frankfurt-1.abc123",
                "source_type": "image"
              }
            ],
            "timeouts": null
          }
        },
        {
          "address": "oci_core_instance.Test123",
          "mode": "managed",
          "type": "oci_core_instance",
          "name": "Test123",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:US-ASHBURN-AD-1",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "create_vnic_details": [
              {
                "assign_public_ip": "true",
                "nsg_ids": null,
                "skip_source_dest_check": false
              }
            ],
            "display_name": "Test123",
            "extended_metadata": null,
            "hostname_label": "test123",
            "metadata": {
              "ssh_authorized_keys": "blah-blah-blah"
            },
            "preserve_boot_volume": null,
            "shape": "VM.Standard1.1",
            "source_details": [
              {
                "source_id": "ocid1.image.oc1.eu-frankfurt-1.abc123",
                "source_type": "image"
              }
            ],
            "timeouts": null
          }
        },
        {
          "address": "oci_core_route_table.Test_Route_1",
          "mode": "managed",
          "type": "oci_core_route_table",
          "name": "Test_Route_1",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "Test_Route_1",
            "route_rules": [
              {
                "destination": "0.0.0.0/0",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.natgateway.oc1.phx.abc123"
              },
              {
                "destination": "1.1.1.0/24",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.servicegateway.oc1.phx.abc123"
              },
              {
                "destination": "10.1.1.0/24",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.natgateway.oc1.phx.abc123"
              },
              {
                "destination": "192.168.0.0/16",
                "destination_type": "CIDR_BLOCK",
                "network_entity_id": "ocid1.servicegateway.oc1.phx.abc123"
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_security_list.test_acl",
          "mode": "managed",
          "type": "oci_core_security_list",
          "name": "test_acl",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_acl",
            "egress_security_rules": [
              {
                "destination": "10.1.2.3/32",
                "destination_type": "CIDR_BLOCK",
                "icmp_options": [],
                "protocol": "all",
                "stateless": true,
                "tcp_options": [],
                "udp_options": []
              },
              {
                "destination": "192.168.0.0/16",
                "destination_type": "CIDR_BLOCK",
                "icmp_options": [],
                "protocol": "17",
                "stateless": true,
                "tcp_options": [],
                "udp_options": [
                  {
                    "max": 1230,
                    "min": 789,
                    "source_port_range": [
                      {
                        "max": 456,
                        "min": 123
                      }
                    ]
                  }
                ]
              }
            ],
            "ingress_security_rules": [
              {
                "icmp_options": [],
                "protocol": "6",
                "source": "10.0.0.1/32",
                "source_type": "CIDR_BLOCK",
                "stateless": false,
                "tcp_options": [
                  {
                    "max": 123,
                    "min": 123,
                    "source_port_range": []
                  }
                ],
                "udp_options": []
              },
              {
                "icmp_options": [],
                "protocol": "all",
                "source": "10.1.2.3/32",
                "source_type": "CIDR_BLOCK",
                "stateless": false,
                "tcp_options": [],
                "udp_options": []
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_security_list.testing-2",
          "mode": "managed",
          "type": "oci_core_security_list",
          "name": "testing-2",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "testing #2",
            "egress_security_rules": [],
            "ingress_security_rules": [
              {
                "icmp_options": [],
                "protocol": "6",
                "source": "10.0.0.1/32",
                "source_type": "CIDR_BLOCK",
                "stateless": false,
                "tcp_options": [
                  {
                    "max": 443,
                    "min": 443,
                    "source_port_range": []
                  }
                ],
                "udp_options": []
              }
            ],
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_subnet.test_subnet_1",
          "mode": "managed",
          "type": "oci_core_subnet",
          "name": "test_subnet_1",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:PHX-AD-1",
            "cidr_block": "192.168.0.0/29",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_subnet_1",
            "dns_label": "testsubnet1",
            "prohibit_public_ip_on_vnic": false,
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_subnet.test_subnet_2",
          "mode": "managed",
          "type": "oci_core_subnet",
          "name": "test_subnet_2",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:PHX-AD-1",
            "cidr_block": "192.168.0.16/28",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_subnet_2",
            "dns_label": "testsubnet2",
            "prohibit_public_ip_on_vnic": false,
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        },
        {
          "address": "oci_core_subnet.test_subnet_3",
          "mode": "managed",
          "type": "oci_core_subnet",
          "name": "test_subnet_3",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "values": {
            "availability_domain": "1234:PHX-AD-1",
            "cidr_block": "192.168.1.0/24",
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_subnet_3",
            "dns_label": "testsubnet3",
            "prohibit_public_ip_on_vnic": false,
            "timeouts": null,
            "vcn_id": "ocid1.vcn.oc1.phx.abc123"
          }
        }
      ]
    }
  }
}

# route tables
test_no_route_target_ids {
  # this tests whether the absence of a value results in success (passes)
  route_target_next_hop_ids_valid with input as invalid_tfplan with allowed_route_target_ids as []
}

test_valid_route_target_ids {
  route_target_next_hop_ids_valid with input as valid_tfplan
}

test_not_valid_route_target_ids {
  not route_target_next_hop_ids_valid with input as invalid_tfplan
}

test_valid_route_target_ids_by_auth_errors {
  auth_errors with input as valid_tfplan == []
}

test_not_valid_route_target_ids_by_auth_errors {
  error_msg = [
    sprintf("ERROR - Route Target next-hop OCID of %v is not within permitted OCIDs (%v).", ["ocid1.internetgateway.oc1.phx.abc123", "ocid1.natgateway.oc1.phx.abc123, ocid1.servicegateway.oc1.phx.abc123"]),
    sprintf("ERROR - Route Target next-hop OCID of %v is not within permitted OCIDs (%v).", ["ocid1.localpeeringgateway.oc1.phx.abc123", "ocid1.natgateway.oc1.phx.abc123, ocid1.servicegateway.oc1.phx.abc123"])
  ]
  bad_input = {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "address": "oci_core_route_table.Test_Route_1",
            "mode": "managed",
            "type": "oci_core_route_table",
            "name": "Test_Route_1",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "compartment_id": "ocid1.compartment.oc1..abc123",
              "display_name": "Test_Route_1",
              "route_rules": [
                {
                  "destination": "0.0.0.0/0",
                  "destination_type": "CIDR_BLOCK",
                  "network_entity_id": "ocid1.internetgateway.oc1.phx.abc123"
                },
                {
                  "destination": "1.1.1.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "network_entity_id": "ocid1.servicegateway.oc1.phx.abc123"
                },
                {
                  "destination": "10.1.1.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "network_entity_id": "ocid1.natgateway.oc1.phx.abc123"
                },
                {
                  "destination": "192.168.0.0/16",
                  "destination_type": "CIDR_BLOCK",
                  "network_entity_id": "ocid1.localpeeringgateway.oc1.phx.abc123"
                }
              ],
              "timeouts": null,
              "vcn_id": "ocid1.vcn.oc1.phx.abc123"
            }
          }
        ]
      }
    }
  }
  output = auth_errors with input as bad_input
  
  some z,i
  matches := [v |
    v := output[z]
    error_msg[i] == v
  ]
  cnt := count(output) - count(matches)
  cnt == 0
}

# compartment OCIDs
test_no_compartment_id {
  # this tests whether the absence of a value results in success (passes)
  compartment_ids_valid with input as invalid_tfplan with allowed_compartment_ids as []
}

test_valid_compartment_id {
  compartment_ids_valid with input as valid_tfplan
}

test_not_valid_compartment_id {
  not compartment_ids_valid with input as invalid_tfplan
}

test_valid_compartment_id_by_auth_errors {
  auth_errors with input as valid_tfplan == []
}

test_not_valid_compartment_id_by_auth_errors {
  error_msg = [
    sprintf("ERROR - Compartment OCID of %v is not within permitted OCIDs (%v).", ["ocid1.123", "ocid1.compartment.oc1..abc123"])
  ]
  bad_input = {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "address": "oci_core_route_table.Test_Route_1",
            "mode": "managed",
            "type": "oci_core_route_table",
            "name": "Test_Route_1",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "compartment_id": "ocid1.123",
              "display_name": "Test_Route_1",
              "timeouts": null,
              "vcn_id": "ocid1.vcn.oc1.phx.abc123"
            }
          }
        ]
      }
    }
  }
  output = auth_errors with input as bad_input
  
  some z,i
  matches := [v |
    v := output[z]
    error_msg[i] == v
  ]
  cnt := count(output) - count(matches)
  cnt == 0
}

# subnet CIDRs
test_no_subnet_cidrs {
  # this tests whether the absence of a value results in success (passes)
  subnet_cidr_in_assigned with input as invalid_tfplan with subnet_allowed_cidrs as []
}

test_valid_subnet_cidrs {
  subnet_cidr_in_assigned with input as valid_tfplan
}

test_not_valid_subnet_cidrs {
  bad_input = {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "address": "oci_core_subnet.test_subnet_3",
            "mode": "managed",
            "type": "oci_core_subnet",
            "name": "test_subnet_3",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "availability_domain": "1234:PHX-AD-1",
              "cidr_block": "192.168.0.16/29",
              "compartment_id": "ocid1.compartment.oc1..abc123",
              "display_name": "test_subnet_3",
              "dns_label": "testsubnet3",
              "prohibit_public_ip_on_vnic": false,
              "timeouts": null,
              "vcn_id": "ocid1.vcn.oc1.phx.abc123"
            }
          },
          {
            "address": "oci_core_subnet.test_subnet_1",
            "mode": "managed",
            "type": "oci_core_subnet",
            "name": "test_subnet_1",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "availability_domain": "1234:PHX-AD-1",
              "cidr_block": "10.168.0.0/29",
              "compartment_id": "ocid1.compartment.oc1..abc123",
              "display_name": "test_subnet_1",
              "dns_label": "testsubnet1",
              "prohibit_public_ip_on_vnic": false,
              "timeouts": null,
              "vcn_id": "ocid1.vcn.oc1.phx.abc123"
            }
          },
          {
            "address": "oci_core_subnet.test_subnet_1",
            "mode": "managed",
            "type": "oci_core_subnet",
            "name": "test_subnet_2",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "availability_domain": "1234:PHX-AD-1",
              "cidr_block": "192.168.0.0/29",
              "compartment_id": "ocid1.compartment.oc1..abc123",
              "display_name": "test_subnet_2",
              "dns_label": "testsubnet2",
              "prohibit_public_ip_on_vnic": false,
              "timeouts": null,
              "vcn_id": "ocid1.vcn.oc1.phx.abc123"
            }
          }
        ]
      }
    }
  }
  not subnet_cidr_in_assigned with input as bad_input
}


# VCN OCIDs
test_no_vcn_id {
  # this tests whether the absence of a value results in success (passes)
  vcn_ids_valid with input as invalid_tfplan with allowed_vcn_ids as []
}

test_valid_vcn_id {
  vcn_ids_valid with input as valid_tfplan
}

test_not_valid_vcn_id {
  not vcn_ids_valid with input as invalid_tfplan
}

test_valid_vcn_id_by_auth_errors {
  auth_errors with input as valid_tfplan == []
}

test_not_valid_vcn_id_by_auth_errors {
  error_msg = [
    sprintf("ERROR - VCN OCID of %v is not within permitted OCIDs (%v).", ["ocid1.vcn.123", "ocid1.vcn.oc1.phx.abc123"])
  ]
  bad_input = {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "address": "oci_core_route_table.Test_Route_1",
            "mode": "managed",
            "type": "oci_core_route_table",
            "name": "Test_Route_1",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "compartment_id": "ocid1.compartment.oc1..abc123",
              "display_name": "Test_Route_1",
              "timeouts": null,
              "vcn_id": "ocid1.vcn.123"
            }
          }
        ]
      }
    }
  }
  output = auth_errors with input as bad_input
  
  some z,i
  matches := [v |
    v := output[z]
    error_msg[i] == v
  ]
  cnt := count(output) - count(matches)
  cnt == 0
}

# resource types
test_no_resource_types {
  # this tests whether the invalid TF plan validates when there's no whitelisted or blacklisted resources (thereby permitting all resources)
  resource_types_allowed with input as invalid_tfplan with allowed_resource_types as [] with blacklisted_resource_types as []
}

test_valid_resource_types {
  resource_types_allowed with input as valid_tfplan
}

test_not_valid_resource_types {
  not resource_types_allowed with input as invalid_tfplan
}

test_valid_resource_types_by_auth_errors {
  auth_errors with input as valid_tfplan == []
}

test_not_valid_resource_types_by_auth_errors_blacklisted {
  error_msg = [
    sprintf("ERROR - Resource type of %v is blacklisted (%v).", ["pac_test_resource", "oci_core_vcn, oci_core_internet_gateway, oci_core_drg, oci_core_local_peering_gateway, oci_identity_compartment, pac_test_resource"])
  ]
  bad_input = {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "address": "pac_test_resource.igw",
            "mode": "managed",
            "type": "pac_test_resource",
            "name": "igw",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "compartment_id": "ocid1.compartment.oc1..abc123",
              "display_name": "Test_Route_1",
              "timeouts": null,
              "vcn_id": "ocid1.vcn.oc1.phx.abc123"
            }
          }
        ]
      }
    }
  }
  output = auth_errors with input as bad_input
  
  some z,i
  matches := [v |
    v := output[z]
    error_msg[i] == v
  ]
  cnt := count(output) - count(matches)
  cnt == 0
}

test_not_valid_resource_types_by_auth_errors_allowed {
  error_msg = [
    sprintf("ERROR - Resource type of %v is not allowed (%v).", ["oci_core_drg_attachment", "oci_core_security_list, oci_core_subnet, oci_core_dhcp_options, oci_core_route_table, oci_core_instance, oci_database_db_system, pac_test_resource"])
  ]
  bad_input = {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "address": "oci_core_drg_attachment.drga",
            "mode": "managed",
            "type": "oci_core_drg_attachment",
            "name": "drga",
            "provider_name": "oci.phx",
            "schema_version": 0,
            "values": {
              "compartment_id": "ocid1.compartment.oc1..abc123",
              "display_name": "Test_Route_1",
              "timeouts": null,
              "vcn_id": "ocid1.vcn.oc1.phx.abc123"
            }
          }
        ]
      }
    }
  }
  output = auth_errors with input as bad_input
  
  some z,i
  matches := [v |
    v := output[z]
    error_msg[i] == v
  ]
  cnt := count(output) - count(matches)
  cnt == 0
}
