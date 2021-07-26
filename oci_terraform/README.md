# Terraform JSON Validation

## Introduction

Terraform can output the plan in JSON form, which makes it particularly easy to validate a given environment using OPA.  This directory (and its subdirectories) show how to validate Terraform plan output using OPA.

## Running

### Dependencies

Dependencies mentioned in the main [README](../README.md) plus the following:

* Terraform v0.12+ (it was the first to introduce the JSON export to `terraform show`).

### Creation of Terraform JSON

Here's what's needed to generate a Terraform plan in JSON (all executed from within a directory with Terraform source code):

```
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
```

With the JSON generated from Terraform, we can now analyze it using OPA.  This has already been done (and abbreviated/sanitized) in the `example/tfplan.json` file.  Feel free to use your own if you prefer (this is highly advised)!

### Validation of Terraform JSON

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/your-awesome-tfplan.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/your-oci_vars.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_policy.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.tf_analysis.authz"
```

You'll want to use real filenames for the TF plan JSON (`your-awesome-tfplan.json` above) as well as the variables rego file (`your-oci_vars.rego` above).

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/your-awesome-tfplan.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/your-oci_vars.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_policy.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.tf_analysis.auth_errors"
```

To quickly see this in action, please look at the examples provided.

## Files

### `example`
This directory has sample/example files for your reference.  For more information, please see the [README](./example/README.md) in this directory.

### `test`
This directory contains the unit tests.  For more information, please see the [README](./test/README.md) in this directory.

### `oci_policy.rego`

This is the file that defines the OPA policy rules.  The following checks are performed by the defined policy rules:

* Do subnet CIDRs fall within the assigned ranges (assigned_cidrs)?
* Do the given TF resource types fall within those specifically whitelisted (allowed_resource_types) and not within the blacklisted resource types (blacklisted_resource_types)?
* Do all of the resources associated to a VCN use the OCIDs of the authorized VCNs (allowed_vcn_ids)?
* Do all resources associated with compartments use only those compartments specifically authorized (allowed_compartment_ids)?
* Do the Route Table rules only use network_entity_ids (next-hop) OCIDs within those allowed (allowed_route_target_ids)?
* Do Security List rules adhere to what's been provided in the `allowed_ingress_rules` and `allowed_egress_rules`?  Here's the logic used:
  * Does the CIDR match any rules defined with "all" protocol? (permit if so, regardless of the protocol or port)
  * Does the CIDR match any rules defined with other (non-"all", 1, 6 or 17) protocols? (permit if so)
  * Does the CIDR match any rules defined for the given protocol (UDP, TCP and ICMP), but without any specific port given?
  * Does the CIDR and port match what's been given by the user?
    * TCP/UDP:
      * Is the user-provided min port greater than or equal to the defined min port?
      * Is the user-provided max port less than or equal to the defined max port?
    * ICMP:
      * Is the type permitted?
      * Is the code permitted (optional, only if provided)?

This is just a sample, so probably doesn't encapsulate all validations, but highlights some of what can be done with an OPA policy.

### `oci_vars.rego`
This is a blank variables file.  One file or many files can be used... or the variables could be placed in the `oci_policy.rego` file.  Either way, OPA needs to be provided the values.  Having the variables totally separate from the policy file in that it's easy to understand what exactly is needed outside of the policy (what the policy is looking for) and also allows for decoupling of the policy and environment-specific variables.

See the `example/oci_vars-pass.rego` for a more complete (filled-out) sample file.

Here's a brief description of the variables in this file:

#### subnet_allowed_cidrs

This is a list where you may put valid Subnet CIDRs in.  Any defined subnet CIDRs will be validated against this list.

If not provided, any subnet CIDR is permitted.

#### allowed_resource_types

This is a list of specific permitted resources that the user can manage.

If both `allowed_resource_types` and `blacklisted_resource_types` are empty (value of `[]`), this effectively permits all resources.

#### blacklisted_resource_types

A list of blacklisted (forbidden) resources that the user is not allowed to manage (should not be present).

If both `allowed_resource_types` and `blacklisted_resource_types` are empty (value of `[]`), this effectively permits all resources.

#### allowed_vcn_ids

A list of VCN OCIDs that are allowed to be used in the environment.

If not provided, any VCN OCID is permitted.

#### allowed_compartment_ids

A list of compartment OCIDs that resources can be associated with in the environment.

If not provided, any compartment is permitted.

#### allowed_route_target_ids

A list of OCIDs of allowed Route Target IDs (gateways, private IPs, etc).  Route Table rule next-hops (targets) are validated against this list.

If not provided, any next-hop (target) is permitted.

#### allowed_ingress_rules
A list of maps which define the permitted ingress (inbound) traffic flows.  These rules are not bound to any specific Subnet or Security List, but rather all Security List (regardless of Security List or associated Subnet) rules are examined.

**NOTE:** If not a blank list is provided for this variable, all Security List rules will fail.  Unlike the other variables, the lack of a provided value does not result in whitelisting all Security List rules.

Each map within the list must have the following values:

| Field | Data Type | Description |
|-------|-----------|-------------|
| protocol | String | The IANA protocol number.  `"all"` is used to designate any protocol.  `"6"` is TCP, `"17"` is UDP, `"1"` is ICMP, etc. |
| cidr | String | The dotted-decimal CIDR for the rule.  If it's an ingress rule this will set the source CIDR while egress rules will designate the destination CIDR. |
| src_port_min | Number | Optional (set to `null` if unused).  The starting (lower) source port number.  Applicable only to TCP and UDP rules. |
| src_port_max | Number | Optional (set to `null` if unused).  The ending (highest) source port number.  Applicable only to TCP and UDP rules. |
| dst_port_min | Number | Optional (set to `null` if unused).  The starting (lower) destination port number.  Applicable only to TCP and UDP rules. |
| dst_port_max | Number | Optional (set to `null` if unused).  The ending (highest) destination port number.  Applicable only to TCP and UDP rules. |
| icmp_type | Number | Optional (set to `null` if unused).  The ICMP Type for the rule (exact match).  Applicable only to ICMP rules. |
| icmp_code | Number | Optional (set to `null` if unused).  The ICMP Code for the rule (exact match).  Applicable only to ICMP rules and only used if the icmp_type is also set to a valid number. |

Even if a map (rule) field is not used (from the above table), it must be provided with a `null` value.

#### allowed_egress_rules

A list of maps which define the permitted egress (outbound) traffic flows.  These rules are not bound to any specific Subnet or Security List, but rather all Security List (regardless of Security List or associated Subnet) rules are examined.

**NOTE:** If not a blank list is provided for this variable, all Security List rules will fail.  Unlike the other variables, the lack of a provided value does not result in whitelisting all Security List rules.

This parameter uses the same format as used for `allowed_ingress_rules` - please refer to it for information on the fields.

## License
Copyright (c) 2021 Oracle and/or its affiliates.

Licensed under the Universal Permissive License (UPL), Version 1.0.

See [LICENSE](../LICENSE) for more details.
