## Copyright (c) 2020, Oracle and/or its affiliates.
## All rights reserved. The Universal Permissive License (UPL), Version 1.0 as shown at http://oss.oracle.com/licenses/upl

package oci.tf_analysis

#----------------------------
# project-specific variables
#----------------------------
# the IP address space that's assigned to this environment
subnet_allowed_cidrs = []
# the types of resources allowed (or prohibited)
allowed_resource_types = []
blacklisted_resource_types = []
# the OCIDs of VCNs that are allowed to be used by this environment
allowed_vcn_ids = []
# specify the compartment OCIDs that can be used by resources in this environment
allowed_compartment_ids = []
# provide the OCIDs of allowed Route Target IDs (gateways, private IPs, etc)
allowed_route_target_ids = []
# permitted Security List rules
allowed_ingress_rules := []
allowed_egress_rules := []
