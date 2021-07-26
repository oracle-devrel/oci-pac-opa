## Copyright (c) 2020, Oracle and/or its affiliates.
## All rights reserved. The Universal Permissive License (UPL), Version 1.0 as shown at http://oss.oracle.com/licenses/upl

package oci.api_analysis

#----------------------------
# project-specific variables
#----------------------------
# the IP address space that's assigned to this environment
subnet_allowed_cidrs = [
  "192.168.0.0/23",
  "192.168.1.0/29"
]
# the OCIDs of VCNs that are allowed to be used by this environment
allowed_vcn_ids = [
  "ocid1.vcn.oc1.phx.<unique_ID-1>"
]
# specify the compartment OCIDs that can be used by resources in this environment
allowed_compartment_ids = [
  "ocid1.compartment.oc1..<unique_ID-1>"
]