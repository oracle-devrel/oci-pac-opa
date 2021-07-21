## Copyright (c) 2020, Oracle and/or its affiliates.
## All rights reserved. The Universal Permissive License (UPL), Version 1.0 as shown at http://oss.oracle.com/licenses/upl

package oci.tf_analysis

import input as tf_in

#----------------------------
# fixed variables
#----------------------------

resources(rez_type) = out {
  some x
  out := [val |
    val := tf_in.planned_values.root_module.resources[x]
    tf_in.planned_values.root_module.resources[x].type == rez_type
  ]
}

security_lists := resources("oci_core_security_list")
sec_list_in_rules := [val |
  val := security_lists[_].values.ingress_security_rules[_]
]
sec_list_eg_rules := [val |
  val := security_lists[_].values.egress_security_rules[_]
]

subnets := resources("oci_core_subnet")

all_compartment_ids_used := [val |
  val := tf_in.planned_values.root_module.resources[_].values.compartment_id
]

route_tables := resources("oci_core_route_table")
all_route_target_next_hop_ids_used := [val |
  val := route_tables[_].values.route_rules[_].network_entity_id
]

all_vcn_ids_used := [val |
  val := tf_in.planned_values.root_module.resources[_].values.vcn_id
]

array_values_permitted_only(permitted_vals, vals_to_check) = true {
  some z,i
  matches := [v |
    v := vals_to_check[z]
    permitted_vals[i] = v
  ]
  cnt := count(vals_to_check) - count(matches)
  cnt == 0
}

array_values_not_permitted_not_found(not_permitted_vals, vals_to_check) = true {
  some z,i
  matches := [v |
    v := vals_to_check[z]
    not_permitted_vals[i] = v
  ]
  cnt := count(matches)
  cnt == 0
}

item_found_in_array(array_to_check, val_to_find) = true {
  some i
  matches := [v |
    v := array_to_check[i]
    val_to_find == v
  ]
  count(matches) > 0
}


#----------------------------
# policy rules
#----------------------------

# this is the main policy that aggregates all others... the final policy
# default authz = false
authz = true {
  route_target_next_hop_ids_valid == true
  vcn_ids_valid == true
  compartment_ids_valid == true
  subnet_cidr_in_assigned == true
  resource_types_allowed == true
  
  count(sec_list_eg_rules_not_permitted_all_proto) == 0
  count(sec_list_eg_rules_not_permitted_other_proto) == 0
  count(sec_list_eg_rules_not_permitted_udp_no_ports) == 0
  count(sec_list_eg_rules_not_permitted_udp_src_ports) == 0
  count(sec_list_eg_rules_not_permitted_udp_dst_ports) == 0
  count(sec_list_eg_rules_not_permitted_udp_src_dst_ports) == 0
  count(sec_list_eg_rules_not_permitted_tcp_no_ports) == 0
  count(sec_list_eg_rules_not_permitted_tcp_src_ports) == 0
  count(sec_list_eg_rules_not_permitted_tcp_dst_ports) == 0
  count(sec_list_eg_rules_not_permitted_tcp_src_dst_ports) == 0
  count(sec_list_eg_rules_not_permitted_icmp_no_type_no_code) == 0
  count(sec_list_eg_rules_not_permitted_icmp_type_no_code) == 0
  count(sec_list_eg_rules_not_permitted_icmp_type_code) == 0
  
  count(sec_list_in_rules_not_permitted_all_proto) == 0
  count(sec_list_in_rules_not_permitted_other_proto) == 0
  count(sec_list_in_rules_not_permitted_udp_no_ports) == 0
  count(sec_list_in_rules_not_permitted_udp_src_ports) == 0
  count(sec_list_in_rules_not_permitted_udp_dst_ports) == 0
  count(sec_list_in_rules_not_permitted_udp_src_dst_ports) == 0
  count(sec_list_in_rules_not_permitted_tcp_no_ports) == 0
  count(sec_list_in_rules_not_permitted_tcp_src_ports) == 0
  count(sec_list_in_rules_not_permitted_tcp_dst_ports) == 0
  count(sec_list_in_rules_not_permitted_tcp_src_dst_ports) == 0
  count(sec_list_in_rules_not_permitted_icmp_no_type_no_code) == 0
  count(sec_list_in_rules_not_permitted_icmp_type_no_code) == 0
  count(sec_list_in_rules_not_permitted_icmp_type_code) == 0
}

#   subnets
# CREDIT TO https://github.com/open-policy-agent/library/blob/master/terraform/library.rego
#   The above example helped me better understand how a Rego policy might be constructed to achieve a particular outcome (and that sets can be used in this way)
subnet_cidr_ok(subnet) {
  net.cidr_contains(subnet_allowed_cidrs[_], subnet.values.cidr_block)
}
subnet_cidr_in_assigned = true {
  count(subnet_allowed_cidrs) == 0
}
subnet_cidr_in_assigned = true {
  count(subnet_allowed_cidrs) > 0
  count(bad_subnets) == 0
}
subnet_cidr_in_assigned = false {
  count(subnet_allowed_cidrs) > 0
  count(bad_subnets) > 0
}
bad_subnets = subs {
#  V specifically this part - didn't know sets could be used like this
  subs := {v | v := subnets[_]
    not subnet_cidr_ok(v)
  }
}
bad_subnet_cidrs = cidrs {
#  V also here - beneficial to know that sets can be dynamically populated like this!
  cidrs := {v | v := bad_subnets[_].values.cidr_block}
}
auth_errors[msg] {
  count(bad_subnets) > 0
  
  msg := sprintf("ERROR - Subnet CIDR(s) %v are not within permitted Subnet CIDR ranges (%v).", [concat(", ", bad_subnet_cidrs), concat(", ", subnet_allowed_cidrs)])
}

#   route table rules
route_target_next_hop_ids_valid = true {
  count(allowed_route_target_ids) == 0
}
route_target_next_hop_ids_valid = true {
  count(allowed_route_target_ids) > 0
  array_values_permitted_only(allowed_route_target_ids, all_route_target_next_hop_ids_used)  
}
auth_errors[msg] {
  some t
  rt_next_hop_id = all_route_target_next_hop_ids_used[_]
  matches := [v |
    v := allowed_route_target_ids[t]
    rt_next_hop_id == v
  ]
  count(matches) == 0
  msg := sprintf("ERROR - Route Target next-hop OCID of %v is not within permitted OCIDs (%v).", [rt_next_hop_id, concat(", ", allowed_route_target_ids)])
}

#   general compartment usage
compartment_ids_valid = true {
  count(allowed_compartment_ids) == 0
}
compartment_ids_valid = true {
  count(allowed_compartment_ids) > 0
  array_values_permitted_only(allowed_compartment_ids, all_compartment_ids_used)  
}
auth_errors[msg] {
  some t
  compartment_id = all_compartment_ids_used[_]
  matches := [v |
    v := allowed_compartment_ids[t]
    compartment_id == v
  ]
  count(matches) == 0
  msg := sprintf("ERROR - Compartment OCID of %v is not within permitted OCIDs (%v).", [compartment_id, concat(", ", allowed_compartment_ids)])
}

#   VCNs used
vcn_ids_valid = true {
  count(allowed_vcn_ids) == 0
}
vcn_ids_valid = true {
  count(allowed_vcn_ids) > 0
  array_values_permitted_only(allowed_vcn_ids, all_vcn_ids_used)
}
auth_errors[msg] {
  some t
  vcn_id = all_vcn_ids_used[_]
  matches := [v |
    v := allowed_vcn_ids[t]
    vcn_id == v
  ]
  count(matches) == 0
  msg := sprintf("ERROR - VCN OCID of %v is not within permitted OCIDs (%v).", [vcn_id, concat(", ", allowed_vcn_ids)])
}

# valid resource type?
resource_types_allowed {
  defined_resource_types := [val |
    val := tf_in.planned_values.root_module.resources[_].type
  ]
  count(allowed_resource_types) > 0
  count(blacklisted_resource_types) > 0
  array_values_permitted_only(allowed_resource_types, defined_resource_types)
  array_values_not_permitted_not_found(blacklisted_resource_types, defined_resource_types)
}
auth_errors[msg] {
  defined_resource_types := [val |
    val := tf_in.planned_values.root_module.resources[_].type
  ]
  count(allowed_resource_types) > 0

  # array_values_permitted_only(allowed_resource_types, defined_resource_types)
  some t
  rez_type = defined_resource_types[_]
  matches := [v |
    v := allowed_resource_types[t]
    rez_type == v
  ]
  count(matches) == 0
  
  msg := sprintf("ERROR - Resource type of %v is not allowed (%v).", [rez_type, concat(", ", allowed_resource_types)])
}
auth_errors[msg] {
  defined_resource_types := [val |
    val := tf_in.planned_values.root_module.resources[_].type
  ]
  count(blacklisted_resource_types) > 0

  # array_values_not_permitted_not_found(blacklisted_resource_types, defined_resource_types)
  some n
  rez_type = defined_resource_types[_]
  disallowed_matches := [v |
    v := blacklisted_resource_types[n]
    rez_type == v
  ]
  count(disallowed_matches) > 0
  
  msg := sprintf("ERROR - Resource type of %v is blacklisted (%v).", [rez_type, concat(", ", blacklisted_resource_types)])
}


resource_types_allowed {
  defined_resource_types := [val |
    val := tf_in.planned_values.root_module.resources[_].type
  ]
  count(allowed_resource_types) == 0
  count(blacklisted_resource_types) > 0
  array_values_not_permitted_not_found(blacklisted_resource_types, defined_resource_types)
}
resource_types_allowed {
  defined_resource_types := [val |
    val := tf_in.planned_values.root_module.resources[_].type
  ]
  count(allowed_resource_types) > 0
  count(blacklisted_resource_types) == 0
  array_values_permitted_only(allowed_resource_types, defined_resource_types)
}
resource_types_allowed {
  count(allowed_resource_types) == 0
  count(blacklisted_resource_types) == 0
}


# Security List validation
# egress rules
allowed_eg_rules_all_proto := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "all"
]
allowed_eg_rules_other_proto := [rule |
  rule := allowed_egress_rules[_]
  not rule.protocol == "all"
  not rule.protocol == "17"
  not rule.protocol == "6"
  not rule.protocol == "1"
]

allowed_eg_rules_udp_no_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "17"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_eg_rules_udp_src_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "17"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]
allowed_eg_rules_udp_dst_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "17"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_eg_rules_udp_src_dst_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "17"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]

allowed_eg_rules_tcp_no_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "6"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_eg_rules_tcp_src_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "6"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]
allowed_eg_rules_tcp_dst_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "6"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_eg_rules_tcp_src_dst_ports := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "6"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]

allowed_eg_rules_icmp_no_type_no_code := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "1"
  is_null(rule.icmp_type) == true
  is_null(rule.icmp_code) == true
]
allowed_eg_rules_icmp_type_no_code := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "1"
  is_number(rule.icmp_type) == true
  is_null(rule.icmp_code) == true
]
allowed_eg_rules_icmp_type_code := [rule |
  rule := allowed_egress_rules[_]
  rule.protocol == "1"
  is_number(rule.icmp_type) == true
  is_number(rule.icmp_code) == true
]

# ingress rules
allowed_in_rules_all_proto := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "all"
]
allowed_in_rules_other_proto := [rule |
  rule := allowed_ingress_rules[_]
  not rule.protocol == "all"
  not rule.protocol == "17"
  not rule.protocol == "6"
  not rule.protocol == "1"
]

allowed_in_rules_udp_no_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "17"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_in_rules_udp_src_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "17"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]
allowed_in_rules_udp_dst_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "17"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_in_rules_udp_src_dst_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "17"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]

allowed_in_rules_tcp_no_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "6"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_in_rules_tcp_src_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "6"
  is_null(rule.dst_port_min) == true
  is_null(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]
allowed_in_rules_tcp_dst_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "6"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_null(rule.src_port_min) == true
  is_null(rule.src_port_max) == true
]
allowed_in_rules_tcp_src_dst_ports := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "6"
  is_number(rule.dst_port_min) == true
  is_number(rule.dst_port_max) == true
  is_number(rule.src_port_min) == true
  is_number(rule.src_port_max) == true
]

allowed_in_rules_icmp_no_type_no_code := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "1"
  is_null(rule.icmp_type) == true
  is_null(rule.icmp_code) == true
]
allowed_in_rules_icmp_type_no_code := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "1"
  is_number(rule.icmp_type) == true
  is_null(rule.icmp_code) == true
]
allowed_in_rules_icmp_type_code := [rule |
  rule := allowed_ingress_rules[_]
  rule.protocol == "1"
  is_number(rule.icmp_type) == true
  is_number(rule.icmp_code) == true
]

# all protocols
eg_rule_matches_allowed({"proto": "all"}, rule) = true {
  matches := [v |
    v := allowed_eg_rules_all_proto[_]
    net.cidr_contains(v.cidr, rule.destination)
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "other"}, rule) = true {
  matches := [v |
    v := allowed_eg_rules_other_proto[_]
    net.cidr_contains(v.cidr, rule.destination)
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "all"}, rule) = true {
  matches := [v |
    v := allowed_in_rules_all_proto[_]
    net.cidr_contains(v.cidr, rule.source)
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "other"}, rule) = true {
  matches := [v |
    v := allowed_in_rules_other_proto[_]
    net.cidr_contains(v.cidr, rule.source)
  ]
  count(matches) > 0
}

# udp
eg_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_udp_no_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_udp_dst_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.udp_options[0].min >= v.dst_port_min
    rule.udp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_udp_src_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.udp_options[0].source_port_range[0].min >= v.src_port_min
    rule.udp_options[0].source_port_range[0].max <= v.src_port_max
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_udp_src_dst_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.udp_options[0].source_port_range[0].min >= v.src_port_min
    rule.udp_options[0].source_port_range[0].max <= v.src_port_max
    rule.udp_options[0].min >= v.dst_port_min
    rule.udp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_udp_no_ports[i]
    net.cidr_contains(v.cidr, rule.source)
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_udp_dst_ports[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.udp_options[0].min >= v.dst_port_min
    rule.udp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_udp_src_ports[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.udp_options[0].source_port_range[0].min >= v.src_port_min
    rule.udp_options[0].source_port_range[0].max <= v.src_port_max
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_udp_src_dst_ports[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.udp_options[0].source_port_range[0].min >= v.src_port_min
    rule.udp_options[0].source_port_range[0].max <= v.src_port_max
    rule.udp_options[0].min >= v.dst_port_min
    rule.udp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}

# tcp
eg_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_tcp_no_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_tcp_dst_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.tcp_options[0].min >= v.dst_port_min
    rule.tcp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_tcp_src_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.tcp_options[0].source_port_range[0].min >= v.src_port_min
    rule.tcp_options[0].source_port_range[0].max <= v.src_port_max
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_tcp_src_dst_ports[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.tcp_options[0].source_port_range[0].min >= v.src_port_min
    rule.tcp_options[0].source_port_range[0].max <= v.src_port_max
    rule.tcp_options[0].min >= v.dst_port_min
    rule.tcp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_tcp_no_ports[i]
    net.cidr_contains(v.cidr, rule.source)
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_tcp_dst_ports[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.tcp_options[0].min >= v.dst_port_min
    rule.tcp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_tcp_src_ports[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.tcp_options[0].source_port_range[0].min >= v.src_port_min
    rule.tcp_options[0].source_port_range[0].max <= v.src_port_max
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_tcp_src_dst_ports[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.tcp_options[0].source_port_range[0].min >= v.src_port_min
    rule.tcp_options[0].source_port_range[0].max <= v.src_port_max
    rule.tcp_options[0].min >= v.dst_port_min
    rule.tcp_options[0].max <= v.dst_port_max
  ]
  count(matches) > 0
}

# icmp
eg_rule_matches_allowed({"proto": "1", "type": false, "code": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_icmp_no_type_no_code[i]
    net.cidr_contains(v.cidr, rule.destination)
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "1", "type": true, "code": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_icmp_type_no_code[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.icmp_options[0].type == v.icmp_type
  ]
  count(matches) > 0
}
eg_rule_matches_allowed({"proto": "1", "type": true, "code": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_eg_rules_icmp_type_code[i]
    net.cidr_contains(v.cidr, rule.destination)
    rule.icmp_options[0].type == v.icmp_type
    rule.icmp_options[0].code == v.icmp_code
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "1", "type": false, "code": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_icmp_no_type_no_code[i]
    net.cidr_contains(v.cidr, rule.source)
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "1", "type": true, "code": false}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_icmp_type_no_code[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.icmp_options[0].type == v.icmp_type
  ]
  count(matches) > 0
}
in_rule_matches_allowed({"proto": "1", "type": true, "code": true}, rule) = true {
  some i
  matches := [v |
    v := allowed_in_rules_icmp_type_code[i]
    net.cidr_contains(v.cidr, rule.source)
    rule.icmp_options[0].type == v.icmp_type
    rule.icmp_options[0].code == v.icmp_code
  ]
  count(matches) > 0
}

# all proto
sec_list_eg_rules_not_permitted_all_proto = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "all"
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
  }
  t := not_permitted
}
sec_list_eg_rules_not_permitted_other_proto = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    not rule.protocol == "all"
    not rule.protocol == "17"
    not rule.protocol == "6"
    not rule.protocol == "1"
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "other"}, v)
  }
  t := not_permitted
}


# udp, no ports
sec_list_eg_rules_not_permitted_udp_no_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "17"
    count(rule.udp_options) == 0
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
  }
  t := not_permitted
}

# udp, dst ports
sec_list_eg_rules_not_permitted_udp_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "17"
    count(rule.udp_options) == 1
    count(rule.udp_options[0]) == 3
    count(rule.udp_options[0].source_port_range) == 0
    is_number(rule.udp_options[0].min) == true
    is_number(rule.udp_options[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed UDP rules
    not eg_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": true}, v)
  }
  t := not_permitted
}

# udp, src ports
sec_list_eg_rules_not_permitted_udp_src_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "17"
    count(rule.udp_options) == 1
    count(rule.udp_options[0]) == 3
    is_null(rule.udp_options[0].min) == true
    is_null(rule.udp_options[0].max) == true
    count(rule.udp_options[0].source_port_range) == 1
    count(rule.udp_options[0].source_port_range[0]) == 2
    is_number(rule.udp_options[0].source_port_range[0].min) == true
    is_number(rule.udp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed UDP rules
    not eg_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": false}, v)
  }
  t := not_permitted
}

# udp, src & dst ports
sec_list_eg_rules_not_permitted_udp_src_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "17"
    
    count(rule.udp_options) == 1
    count(rule.udp_options[0]) == 3
    is_number(rule.udp_options[0].min) == true
    is_number(rule.udp_options[0].max) == true
    count(rule.udp_options[0].source_port_range) == 1
    count(rule.udp_options[0].source_port_range[0]) == 2
    is_number(rule.udp_options[0].source_port_range[0].min) == true
    is_number(rule.udp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed UDP rules
    not eg_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": true}, v)
  }
  t := not_permitted
}

# tcp, no ports
sec_list_eg_rules_not_permitted_tcp_no_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "6"
    count(rule.tcp_options) == 0
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
  }
  t := not_permitted
}

# tcp, dst ports
sec_list_eg_rules_not_permitted_tcp_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "6"
    count(rule.tcp_options) == 1
    count(rule.tcp_options[0]) == 3
    count(rule.tcp_options[0].source_port_range) == 0
    is_number(rule.tcp_options[0].min) == true
    is_number(rule.tcp_options[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed tcp rules
    not eg_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": true}, v)
  }
  t := not_permitted
}

# tcp, src ports
sec_list_eg_rules_not_permitted_tcp_src_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "6"
    count(rule.tcp_options) == 1
    count(rule.tcp_options[0]) == 3
    is_null(rule.tcp_options[0].min) == true
    is_null(rule.tcp_options[0].max) == true
    count(rule.tcp_options[0].source_port_range) == 1
    count(rule.tcp_options[0].source_port_range[0]) == 2
    is_number(rule.tcp_options[0].source_port_range[0].min) == true
    is_number(rule.tcp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed tcp rules
    not eg_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": false}, v)
  }
  t := not_permitted
}

# tcp, src & dst ports
sec_list_eg_rules_not_permitted_tcp_src_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "6"
    
    count(rule.tcp_options) == 1
    count(rule.tcp_options[0]) == 3
    is_number(rule.tcp_options[0].min) == true
    is_number(rule.tcp_options[0].max) == true
    count(rule.tcp_options[0].source_port_range) == 1
    count(rule.tcp_options[0].source_port_range[0]) == 2
    is_number(rule.tcp_options[0].source_port_range[0].min) == true
    is_number(rule.tcp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed tcp rules
    not eg_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": true}, v)
  }
  t := not_permitted
}

# icmp, no type, no code
sec_list_eg_rules_not_permitted_icmp_no_type_no_code = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "1"
    count(rule.icmp_options) == 0
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed icmp rules with no parameters (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "1", "type": false, "code": false}, v)
  }
  t := not_permitted
}

# icmp, type, no code
sec_list_eg_rules_not_permitted_icmp_type_no_code = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "1"
    count(rule.icmp_options) == 1
    count(rule.icmp_options[0]) == 2
    is_number(rule.icmp_options[0].type) == true
    is_null(rule.icmp_options[0].code) == true
    not rule.icmp_options[0].type == -1
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed icmp rules with no parameters (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "1", "type": false, "code": false}, v)
    # now look at the more-specific allowed icmp rules
    not eg_rule_matches_allowed({"proto": "1", "type": true, "code": false}, v)
  }
  t := not_permitted
}

# icmp, type & code
sec_list_eg_rules_not_permitted_icmp_type_code = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_eg_rules[_]
    rule.protocol == "1"
    count(rule.icmp_options) == 1
    count(rule.icmp_options[0]) == 2
    is_number(rule.icmp_options[0].type) == true
    is_number(rule.icmp_options[0].code) == true
    not rule.icmp_options[0].type == -1
    not rule.icmp_options[0].code == -1
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not eg_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed icmp rules with no parameters (in case it will match this rule)
    not eg_rule_matches_allowed({"proto": "1", "type": false, "code": false}, v)
    # now look at the more-specific allowed icmp rules
    not eg_rule_matches_allowed({"proto": "1", "type": true, "code": false}, v)
    # now look at the even more-specific allowed icmp rules
    not eg_rule_matches_allowed({"proto": "1", "type": true, "code": true}, v)
  }
  t := not_permitted
}

# auth errors for egress security list rules
auth_errors[msg] {
  not_matched_all_proto := sec_list_eg_rules_not_permitted_all_proto
  not_matched_other_proto := sec_list_eg_rules_not_permitted_other_proto

  not_matched_udp_no_ports := sec_list_eg_rules_not_permitted_udp_no_ports
  not_matched_udp_src_ports := sec_list_eg_rules_not_permitted_udp_src_ports
  not_matched_udp_dst_ports := sec_list_eg_rules_not_permitted_udp_dst_ports
  not_matched_udp_src_dst_ports := sec_list_eg_rules_not_permitted_udp_src_dst_ports

  not_matched_tcp_no_ports := sec_list_eg_rules_not_permitted_tcp_no_ports
  not_matched_tcp_src_ports := sec_list_eg_rules_not_permitted_tcp_src_ports
  not_matched_tcp_dst_ports := sec_list_eg_rules_not_permitted_tcp_dst_ports
  not_matched_tcp_src_dst_ports := sec_list_eg_rules_not_permitted_tcp_src_dst_ports

  not_matched_icmp_no_type_no_code := sec_list_eg_rules_not_permitted_icmp_no_type_no_code
  not_matched_icmp_type_no_code := sec_list_eg_rules_not_permitted_icmp_type_no_code
  not_matched_icmp_type_code := sec_list_eg_rules_not_permitted_icmp_type_code
  
  not_matched := not_matched_all_proto | not_matched_other_proto | not_matched_udp_no_ports | not_matched_udp_src_ports | not_matched_udp_dst_ports | not_matched_udp_src_dst_ports | not_matched_tcp_no_ports | not_matched_tcp_src_ports | not_matched_tcp_dst_ports | not_matched_tcp_src_dst_ports | not_matched_icmp_no_type_no_code | not_matched_icmp_type_no_code | not_matched_icmp_type_code
  # convert from set of objects to set of strings (so concat will work properly below)
  all_not_matched := {p |
    p := sprintf("%v", [not_matched[_]])
  }
  
  count(all_not_matched) > 0
  msg := sprintf("ERROR - The following Security List egress rules are not allowed:\n\n%v.", [concat("\n", all_not_matched)])
}

# all proto
sec_list_in_rules_not_permitted_all_proto = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "all"
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
  }
  t := not_permitted
}
sec_list_in_rules_not_permitted_other_proto = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    not rule.protocol == "all"
    not rule.protocol == "17"
    not rule.protocol == "6"
    not rule.protocol == "1"
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "other"}, v)
  }
  t := not_permitted
}


# udp, no ports
sec_list_in_rules_not_permitted_udp_no_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "17"
    count(rule.udp_options) == 0
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
  }
  t := not_permitted
}

# udp, dst ports
sec_list_in_rules_not_permitted_udp_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "17"
    count(rule.udp_options) == 1
    count(rule.udp_options[0]) == 3
    count(rule.udp_options[0].source_port_range) == 0
    is_number(rule.udp_options[0].min) == true
    is_number(rule.udp_options[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed UDP rules
    not in_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": true}, v)
  }
  t := not_permitted
}

# udp, src ports
sec_list_in_rules_not_permitted_udp_src_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "17"
    count(rule.udp_options) == 1
    count(rule.udp_options[0]) == 3
    is_null(rule.udp_options[0].min) == true
    is_null(rule.udp_options[0].max) == true
    count(rule.udp_options[0].source_port_range) == 1
    count(rule.udp_options[0].source_port_range[0]) == 2
    is_number(rule.udp_options[0].source_port_range[0].min) == true
    is_number(rule.udp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed UDP rules
    not in_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": false}, v)
  }
  t := not_permitted
}

# udp, src & dst ports
sec_list_in_rules_not_permitted_udp_src_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "17"
    
    count(rule.udp_options) == 1
    count(rule.udp_options[0]) == 3
    is_number(rule.udp_options[0].min) == true
    is_number(rule.udp_options[0].max) == true
    count(rule.udp_options[0].source_port_range) == 1
    count(rule.udp_options[0].source_port_range[0]) == 2
    is_number(rule.udp_options[0].source_port_range[0].min) == true
    is_number(rule.udp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed UDP rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "17", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed UDP rules
    not in_rule_matches_allowed({"proto": "17", "src_port": true, "dst_port": true}, v)
  }
  t := not_permitted
}

# tcp, no ports
sec_list_in_rules_not_permitted_tcp_no_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "6"
    count(rule.tcp_options) == 0
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
  }
  t := not_permitted
}

# tcp, dst ports
sec_list_in_rules_not_permitted_tcp_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "6"
    count(rule.tcp_options) == 1
    count(rule.tcp_options[0]) == 3
    count(rule.tcp_options[0].source_port_range) == 0
    is_number(rule.tcp_options[0].min) == true
    is_number(rule.tcp_options[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed tcp rules
    not in_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": true}, v)
  }
  t := not_permitted
}

# tcp, src ports
sec_list_in_rules_not_permitted_tcp_src_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "6"
    count(rule.tcp_options) == 1
    count(rule.tcp_options[0]) == 3
    is_null(rule.tcp_options[0].min) == true
    is_null(rule.tcp_options[0].max) == true
    count(rule.tcp_options[0].source_port_range) == 1
    count(rule.tcp_options[0].source_port_range[0]) == 2
    is_number(rule.tcp_options[0].source_port_range[0].min) == true
    is_number(rule.tcp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed tcp rules
    not in_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": false}, v)
  }
  t := not_permitted
}

# tcp, src & dst ports
sec_list_in_rules_not_permitted_tcp_src_dst_ports = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "6"
    
    count(rule.tcp_options) == 1
    count(rule.tcp_options[0]) == 3
    is_number(rule.tcp_options[0].min) == true
    is_number(rule.tcp_options[0].max) == true
    count(rule.tcp_options[0].source_port_range) == 1
    count(rule.tcp_options[0].source_port_range[0]) == 2
    is_number(rule.tcp_options[0].source_port_range[0].min) == true
    is_number(rule.tcp_options[0].source_port_range[0].max) == true
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed tcp rules with no ports (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "6", "src_port": false, "dst_port": false}, v)
    # now look at the more-specific allowed tcp rules
    not in_rule_matches_allowed({"proto": "6", "src_port": true, "dst_port": true}, v)
  }
  t := not_permitted
}

# icmp, no type, no code
sec_list_in_rules_not_permitted_icmp_no_type_no_code = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "1"
    count(rule.icmp_options) == 0
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed icmp rules with no parameters (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "1", "type": false, "code": false}, v)
  }
  t := not_permitted
}

# icmp, type, no code
sec_list_in_rules_not_permitted_icmp_type_no_code = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "1"
    count(rule.icmp_options) == 1
    count(rule.icmp_options[0]) == 2
    is_number(rule.icmp_options[0].type) == true
    is_null(rule.icmp_options[0].code) == true
    not rule.icmp_options[0].type == -1
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed icmp rules with no parameters (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "1", "type": false, "code": false}, v)
    # now look at the more-specific allowed icmp rules
    not in_rule_matches_allowed({"proto": "1", "type": true, "code": false}, v)
  }
  t := not_permitted
}

# icmp, type & code
sec_list_in_rules_not_permitted_icmp_type_code = t {
  # filter user-provided rules
  rules := [rule |
    rule := sec_list_in_rules[_]
    rule.protocol == "1"
    count(rule.icmp_options) == 1
    count(rule.icmp_options[0]) == 2
    is_number(rule.icmp_options[0].type) == true
    is_number(rule.icmp_options[0].code) == true
    not rule.icmp_options[0].type == -1
    not rule.icmp_options[0].code == -1
  ]
  
  not_permitted := {v |
    v := rules[_]
    # match failures (not true)
    # look at all allowed protocols
    not in_rule_matches_allowed({"proto": "all"}, v)
    # look at the allowed icmp rules with no parameters (in case it will match this rule)
    not in_rule_matches_allowed({"proto": "1", "type": false, "code": false}, v)
    # now look at the more-specific allowed icmp rules
    not in_rule_matches_allowed({"proto": "1", "type": true, "code": false}, v)
    # now look at the even more-specific allowed icmp rules
    not in_rule_matches_allowed({"proto": "1", "type": true, "code": true}, v)
  }
  t := not_permitted
}

# auth errors for ingress security list rules
auth_errors[msg] {
  not_matched_all_proto := sec_list_in_rules_not_permitted_all_proto
  not_matched_other_proto := sec_list_in_rules_not_permitted_other_proto

  not_matched_udp_no_ports := sec_list_in_rules_not_permitted_udp_no_ports
  not_matched_udp_src_ports := sec_list_in_rules_not_permitted_udp_src_ports
  not_matched_udp_dst_ports := sec_list_in_rules_not_permitted_udp_dst_ports
  not_matched_udp_src_dst_ports := sec_list_in_rules_not_permitted_udp_src_dst_ports

  not_matched_tcp_no_ports := sec_list_in_rules_not_permitted_tcp_no_ports
  not_matched_tcp_src_ports := sec_list_in_rules_not_permitted_tcp_src_ports
  not_matched_tcp_dst_ports := sec_list_in_rules_not_permitted_tcp_dst_ports
  not_matched_tcp_src_dst_ports := sec_list_in_rules_not_permitted_tcp_src_dst_ports

  not_matched_icmp_no_type_no_code := sec_list_in_rules_not_permitted_icmp_no_type_no_code
  not_matched_icmp_type_no_code := sec_list_in_rules_not_permitted_icmp_type_no_code
  not_matched_icmp_type_code := sec_list_in_rules_not_permitted_icmp_type_code
  
  not_matched := not_matched_all_proto | not_matched_other_proto | not_matched_udp_no_ports | not_matched_udp_src_ports | not_matched_udp_dst_ports | not_matched_udp_src_dst_ports | not_matched_tcp_no_ports | not_matched_tcp_src_ports | not_matched_tcp_dst_ports | not_matched_tcp_src_dst_ports | not_matched_icmp_no_type_no_code | not_matched_icmp_type_no_code | not_matched_icmp_type_code
  # convert from set of objects to set of strings (so concat will work properly below)
  all_not_matched := {p |
    p := sprintf("%v", [not_matched[_]])
  }
  
  count(all_not_matched) > 0
  msg := sprintf("ERROR - The following Security List ingress rules are not allowed:\n\n%v.", [concat("\n", all_not_matched)])
}
