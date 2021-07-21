# OCI API JSON Validation

The OCI API returns JSON, which is what OPA likes to evaluate, so... here's an example scenario of how to use OPA to look at data that the OCI API might return.  This particular example is looking at a few Subnet attributes.

## Files

### `examples`
This directory has a sample/example files for your reference.  For more information, please see the [README](./examples/README.md) in this directory.

### `oci_policy_subnet.rego`

This is the file that defines the sample Subnet OPA policy rules.  The following checks are performed by the policy rules:

* The IP address that's assigned to the Subnet
* The VCN OCIDs that Subnets can use
* The compartment OCIDs that can be used by Subnets

This is just a sample, so probably doesn't encapsulate all validations, but highlights some of what can be done with an OPA policy.

### `oci_vars.rego`
This is a blank variables file.  One file or many files can be used... or the variables could be placed in the `oci_policy.rego` file.  Either way, OPA needs to be provided the values.  Having the variables totally separate from the policy file in that it's easy to understand what exactly is needed outside of the policy (what the policy is looking for) and also allows for decoupling of the policy and environment-specific variables.

See the `examples/oci_vars-pass.rego` for a more complete (filled-out) sample file.

## License
Copyright (c) 2021 Oracle and/or its affiliates.

Licensed under the Universal Permissive License (UPL), Version 1.0.

See [LICENSE](../LICENSE) for more details.