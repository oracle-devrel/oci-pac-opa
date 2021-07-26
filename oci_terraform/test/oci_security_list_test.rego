## Copyright (c) 2020, Oracle and/or its affiliates.
## All rights reserved. The Universal Permissive License (UPL), Version 1.0 as shown at http://oss.oracle.com/licenses/upl

package oci.tf_analysis

# Security list testing
# egress
test_allowed_eg_rules_all_proto {
  t := allowed_eg_rules_all_proto
  count(t) == 1
  t[0].cidr == "10.0.0.0/24"
}

test_allowed_eg_rules_other_proto {
  t := allowed_eg_rules_other_proto
  count(t) == 1
  t[0].cidr == "10.0.99.0/24"
}

test_allowed_eg_rules_udp_dst_ports {
  t := allowed_eg_rules_udp_dst_ports
  count(t) == 1
  t[0].cidr == "10.0.1.0/24"
}

test_allowed_eg_rules_udp_src_ports {
  t := allowed_eg_rules_udp_src_ports
  count(t) == 1
  t[0].cidr == "10.0.2.0/24"
}

test_allowed_eg_rules_udp_src_dst_ports {
  t := allowed_eg_rules_udp_src_dst_ports
  count(t) == 1
  t[0].cidr == "10.0.3.0/24"
}

test_allowed_eg_rules_udp_no_ports {
  t := allowed_eg_rules_udp_no_ports
  count(t) == 1
  t[0].cidr == "10.0.4.0/24"
}

test_allowed_eg_rules_tcp_dst_ports {
  t := allowed_eg_rules_tcp_dst_ports
  count(t) == 1
  t[0].cidr == "10.0.1.0/24"
}

test_allowed_eg_rules_tcp_src_ports {
  t := allowed_eg_rules_tcp_src_ports
  count(t) == 1
  t[0].cidr == "10.0.2.0/24"
}

test_allowed_eg_rules_tcp_src_dst_ports {
  t := allowed_eg_rules_tcp_src_dst_ports
  count(t) == 1
  t[0].cidr == "10.0.3.0/24"
}

test_allowed_eg_rules_icmp_no_type_no_code {
  t := allowed_eg_rules_icmp_no_type_no_code
  count(t) == 1
  t[0].cidr == "10.0.5.0/24"
}

test_allowed_eg_rules_icmp_type_no_code {
  t := allowed_eg_rules_icmp_type_no_code
  count(t) == 1
  t[0].cidr == "10.0.6.0/24"
}

test_allowed_eg_rules_icmp_type_code {
  t := allowed_eg_rules_icmp_type_code
  count(t) == 1
  t[0].cidr == "10.0.7.0/24"
}

# all proto
test_sec_list_eg_rules_not_permitted_all_proto_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.0.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "all",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_all_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_all_proto_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_all_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_all_proto_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "all",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_all_proto with input as test_input
  
  count(output) == 1
}

# other (non-all, 1, 6 or 17) proto
test_sec_list_eg_rules_not_permitted_other_proto_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.99.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "51",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "50",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_other_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_other_proto_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_other_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_other_proto_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "50",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_other_proto with input as test_input
  
  count(output) == 1
}

# icmp, no type, no code
test_sec_list_eg_rules_not_permitted_icmp_no_type_no_code_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.5.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_no_type_no_code with input as test_input
  
  count(output) == 0
}
test_sec_list_eg_rules_not_permitted_icmp_no_type_no_code_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.5.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_no_type_no_code with input as test_input
  
  count(output) == 1
}

# icmp, type, no code
test_sec_list_eg_rules_not_permitted_icmp_type_no_code_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.6.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 8,
                      "code": null
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_type_no_code with input as test_input
  
  count(output) == 0
}
test_sec_list_eg_rules_not_permitted_icmp_type_no_code_bad_val_type {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.6.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 10,
                      "code": null
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_type_no_code with input as test_input
  
  count(output) == 1
}
test_sec_list_eg_rules_not_permitted_icmp_type_no_code_bad_val_ip {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.6.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 8,
                      "code": null
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_type_no_code with input as test_input
  
  count(output) == 1
}
# icmp, type, code
test_sec_list_eg_rules_not_permitted_icmp_type_code_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.7.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 3,
                      "code": 4
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 0
}
test_sec_list_eg_rules_not_permitted_icmp_type_code_bad_val_type {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.7.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 10,
                      "code": 4
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 1
}
test_sec_list_eg_rules_not_permitted_icmp_type_code_bad_val_code {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.7.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 3,
                      "code": 10
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 1
}
test_sec_list_eg_rules_not_permitted_icmp_type_code_bad_val_ip {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.7.0/24",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 3,
                      "code": 4
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 1
}

# UDP, no ports
test_sec_list_eg_rules_not_permitted_udp_no_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_no_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_no_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_no_ports with input as test_input
  
  count(output) == 1
}

# UDP, dst ports
test_sec_list_eg_rules_not_permitted_udp_dst_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "destination": "10.0.1.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "destination": "10.0.1.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_dst_ports with input as test_input
  
  count(output) == 2
}

# UDP, src ports
test_sec_list_eg_rules_not_permitted_udp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.2.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_src_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_src_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.2.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1230,
                          "min": 789,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_src_ports with input as test_input
  
  count(output) == 2
}

# UDP, src & dst ports
test_sec_list_eg_rules_not_permitted_udp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.3.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_src_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
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
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_udp_src_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.3.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 5123,
                      "min": 1234,
                      "source_port_range": [
                        {
                          "max": 1230,
                          "min": 789,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.3.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 1230,
                          "min": 789,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.3.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 5123,
                      "min": 1234,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_udp_src_dst_ports with input as test_input
  
  count(output) == 4
}

# TCP, no ports
test_sec_list_eg_rules_not_permitted_tcp_no_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_no_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_no_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_no_ports with input as test_input
  
  count(output) == 1
}

# UDP, dst ports
test_sec_list_eg_rules_not_permitted_tcp_dst_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.1.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.1.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_dst_ports with input as test_input
  
  count(output) == 2
}

# UDP, src ports
test_sec_list_eg_rules_not_permitted_tcp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.2.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_src_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_src_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.2.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 4430,
                          "min": 789,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_src_ports with input as test_input
  
  count(output) == 2
}

# tcp, src & dst ports
test_sec_list_eg_rules_not_permitted_tcp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.3.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_src_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.0.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "destination": "10.0.4.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_eg_rules_not_permitted_tcp_src_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.3.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 5443,
                      "min": 4434,
                      "source_port_range": [
                        {
                          "max": 4430,
                          "min": 789,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.3.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 4430,
                          "min": 789,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.3.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 5443,
                      "min": 4434,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "destination": "10.0.0.1/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_eg_rules_not_permitted_tcp_src_dst_ports with input as test_input
  
  count(output) == 4
}

## auth errors - security list errors
test_sec_list_eg_auth_errors {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
                  "destination": "10.1.4.3/32",
                  "destination_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = auth_errors with input as test_input
  
  count(output) == 1
  
  bad_rule := "{\"destination\": \"10.1.4.3/32\", \"destination_type\": \"CIDR_BLOCK\", \"icmp_options\": [], \"protocol\": \"17\", \"stateless\": true, \"tcp_options\": [], \"udp_options\": [{\"max\": 123, \"min\": 123, \"source_port_range\": [{\"max\": 123, \"min\": 123}]}]}"
  error_msg = {
    sprintf("ERROR - The following Security List egress rules are not allowed:\n\n%v.", [bad_rule])
  }
  output == error_msg
}








# ingress
test_allowed_in_rules_all_proto {
  t := allowed_in_rules_all_proto
  count(t) == 1
  t[0].cidr == "10.1.0.0/24"
}

test_allowed_in_rules_other_proto {
  t := allowed_in_rules_other_proto
  count(t) == 1
  t[0].cidr == "10.1.99.0/24"
}

test_allowed_in_rules_udp_dst_ports {
  t := allowed_in_rules_udp_dst_ports
  count(t) == 1
  t[0].cidr == "10.1.1.0/24"
}

test_allowed_in_rules_udp_src_ports {
  t := allowed_in_rules_udp_src_ports
  count(t) == 1
  t[0].cidr == "10.1.2.0/24"
}

test_allowed_in_rules_udp_src_dst_ports {
  t := allowed_in_rules_udp_src_dst_ports
  count(t) == 1
  t[0].cidr == "10.1.3.0/24"
}

test_allowed_in_rules_udp_no_ports {
  t := allowed_in_rules_udp_no_ports
  count(t) == 1
  t[0].cidr == "10.1.4.0/24"
}

test_allowed_in_rules_tcp_dst_ports {
  t := allowed_in_rules_tcp_dst_ports
  count(t) == 1
  t[0].cidr == "10.1.1.0/24"
}

test_allowed_in_rules_tcp_src_ports {
  t := allowed_in_rules_tcp_src_ports
  count(t) == 1
  t[0].cidr == "10.1.2.0/24"
}

test_allowed_in_rules_tcp_src_dst_ports {
  t := allowed_in_rules_tcp_src_dst_ports
  count(t) == 1
  t[0].cidr == "10.1.3.0/24"
}

test_allowed_in_rules_icmp_no_type_no_code {
  t := allowed_in_rules_icmp_no_type_no_code
  count(t) == 1
  t[0].cidr == "10.1.5.0/24"
}

test_allowed_in_rules_icmp_type_no_code {
  t := allowed_in_rules_icmp_type_no_code
  count(t) == 1
  t[0].cidr == "10.1.6.0/24"
}

test_allowed_in_rules_icmp_type_code {
  t := allowed_in_rules_icmp_type_code
  count(t) == 1
  t[0].cidr == "10.1.7.0/24"
}

# all proto
test_sec_list_in_rules_not_permitted_all_proto_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.0.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "all",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_all_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_all_proto_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_all_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_all_proto_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "all",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_all_proto with input as test_input
  
  count(output) == 1
}

# other (non-all, 1, 6 or 17) proto
test_sec_list_in_rules_not_permitted_other_proto_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.99.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "51",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "50",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_other_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_other_proto_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_other_proto with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_other_proto_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "50",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_other_proto with input as test_input
  
  count(output) == 1
}

# icmp, no type, no code
test_sec_list_in_rules_not_permitted_icmp_no_type_no_code_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.5.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_no_type_no_code with input as test_input
  
  count(output) == 0
}
test_sec_list_in_rules_not_permitted_icmp_no_type_no_code_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.5.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_no_type_no_code with input as test_input
  
  count(output) == 1
}

# icmp, type, no code
test_sec_list_in_rules_not_permitted_icmp_type_no_code_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.6.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 8,
                      "code": null
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_type_no_code with input as test_input
  
  count(output) == 0
}
test_sec_list_in_rules_not_permitted_icmp_type_no_code_bad_val_type {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.6.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 10,
                      "code": null
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_type_no_code with input as test_input
  
  count(output) == 1
}
test_sec_list_in_rules_not_permitted_icmp_type_no_code_bad_val_ip {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.6.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 8,
                      "code": null
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_type_no_code with input as test_input
  
  count(output) == 1
}
# icmp, type, code
test_sec_list_in_rules_not_permitted_icmp_type_code_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.7.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 3,
                      "code": 4
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 0
}
test_sec_list_in_rules_not_permitted_icmp_type_code_bad_val_type {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.7.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 10,
                      "code": 4
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 1
}
test_sec_list_in_rules_not_permitted_icmp_type_code_bad_val_code {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.7.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 3,
                      "code": 10
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 1
}
test_sec_list_in_rules_not_permitted_icmp_type_code_bad_val_ip {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.7.0/24",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [
                    {
                      "type": 3,
                      "code": 4
                    }
                  ],
                  "protocol": "1",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_icmp_type_code with input as test_input
  
  count(output) == 1
}

# UDP, no ports
test_sec_list_in_rules_not_permitted_udp_no_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_no_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_no_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_no_ports with input as test_input
  
  count(output) == 1
}

# UDP, dst ports
test_sec_list_in_rules_not_permitted_udp_dst_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "source": "10.1.1.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "source": "10.1.1.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 1230,
                      "min": 789,
                      "source_port_range": []
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_dst_ports with input as test_input
  
  count(output) == 2
}

# UDP, src ports
test_sec_list_in_rules_not_permitted_udp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.2.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_src_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_src_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.2.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1230,
                          "min": 789,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_src_ports with input as test_input
  
  count(output) == 2
}

# UDP, src & dst ports
test_sec_list_in_rules_not_permitted_udp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.3.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_src_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
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
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_udp_src_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.3.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 5123,
                      "min": 1234,
                      "source_port_range": [
                        {
                          "max": 1230,
                          "min": 789,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.3.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 1230,
                          "min": 789,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.3.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 5123,
                      "min": 1234,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 1230,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_udp_src_dst_ports with input as test_input
  
  count(output) == 4
}

# TCP, no ports
test_sec_list_in_rules_not_permitted_tcp_no_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_no_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_no_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_no_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_no_ports with input as test_input
  
  count(output) == 1
}

# UDP, dst ports
test_sec_list_in_rules_not_permitted_tcp_dst_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.1.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.1.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": []
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_dst_ports with input as test_input
  
  count(output) == 2
}

# UDP, src ports
test_sec_list_in_rules_not_permitted_tcp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.2.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_src_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_src_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_src_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.2.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 4430,
                          "min": 789,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": null,
                      "min": null,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_src_ports with input as test_input
  
  count(output) == 2
}

# tcp, src & dst ports
test_sec_list_in_rules_not_permitted_tcp_src_ports_good_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.3.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_src_dst_ports_no_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.1.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": []
                },
                {
                  "source": "10.1.4.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 4430,
                      "min": 789,
                      "source_port_range": [
                        {
                          "max": 456,
                          "min": 443
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_src_dst_ports with input as test_input
  
  count(output) == 0
}

test_sec_list_in_rules_not_permitted_tcp_src_dst_ports_bad_val {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.3.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 5443,
                      "min": 4434,
                      "source_port_range": [
                        {
                          "max": 4430,
                          "min": 789,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.3.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 443,
                      "min": 443,
                      "source_port_range": [
                        {
                          "max": 4430,
                          "min": 789,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.3.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 5443,
                      "min": 4434,
                      "source_port_range": [
                        {
                          "max": 443,
                          "min": 443,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                },
                {
                  "source": "10.1.0.1/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "6",
                  "stateless": true,
                  "tcp_options": [
                    {
                      "max": 456,
                      "min": 456,
                      "source_port_range": [
                        {
                          "max": 1250,
                          "min": 4430,
                        }
                      ]
                    }
                  ],
                  "udp_options": []
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = sec_list_in_rules_not_permitted_tcp_src_dst_ports with input as test_input
  
  count(output) == 4
}

## auth errors - security list errors
test_sec_list_in_auth_errors {
  test_input := {
    "planned_values": {
      "root_module": {
        "resources": [
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
              "ingress_security_rules": [
                {
                  "source": "10.0.4.3/32",
                  "source_type": "CIDR_BLOCK",
                  "icmp_options": [],
                  "protocol": "17",
                  "stateless": true,
                  "tcp_options": [],
                  "udp_options": [
                    {
                      "max": 123,
                      "min": 123,
                      "source_port_range": [
                        {
                          "max": 123,
                          "min": 123,
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  }
  output = auth_errors with input as test_input
  
  count(output) == 1
  
  bad_rule := "{\"icmp_options\": [], \"protocol\": \"17\", \"source\": \"10.0.4.3/32\", \"source_type\": \"CIDR_BLOCK\", \"stateless\": true, \"tcp_options\": [], \"udp_options\": [{\"max\": 123, \"min\": 123, \"source_port_range\": [{\"max\": 123, \"min\": 123}]}]}"
  error_msg = {
    sprintf("ERROR - The following Security List ingress rules are not allowed:\n\n%v.", [bad_rule])
  }
  output == error_msg
}