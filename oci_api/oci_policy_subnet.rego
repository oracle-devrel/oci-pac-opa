## Copyright (c) 2020, Oracle and/or its affiliates.
## All rights reserved. The Universal Permissive License (UPL), Version 1.0 as shown at http://oss.oracle.com/licenses/upl

package oci.api_analysis

import input as api_in

#----------------------------
# fixed variables
#----------------------------

resources = out {
  is_array(api_in)
  out := api_in
}

resources = out {
  not is_array(api_in)
  out := [api_in]
}

all_compartment_ids_used := [val |
  val := resources[_].compartmentId
]

all_vcn_ids_used := [val |
  val := resources[_].vcnId
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
authz = true {
  vcn_ids_valid == true
  compartment_ids_valid == true
  subnet_cidr_in_assigned == true
}

#   subnets
subnet_cidr_ok(subnet) {
  net.cidr_contains(subnet_allowed_cidrs[_], subnet.cidrBlock)
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
  subs := {v | v := resources[_]
    not subnet_cidr_ok(v)
  }
}
bad_subnet_cidrs = cidrs {
#  V also here - beneficial to know that sets can be dynamically populated like this!
  cidrs := {v | v := bad_subnets[_].cidrBlock}
}
auth_errors[msg] {
  count(bad_subnets) > 0
  
  msg := sprintf("ERROR - Subnet CIDR(s) %v are not within permitted Subnet CIDR ranges (%v).", [concat(", ", bad_subnet_cidrs), concat(", ", subnet_allowed_cidrs)])
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