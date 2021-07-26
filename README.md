# Policy-as-Code on OCI Using Open Policy Agent

[![License: UPL](https://img.shields.io/badge/license-UPL-green)](https://img.shields.io/badge/license-UPL-green) [![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=oracle-devrel_oci-pac-opa)](https://sonarcloud.io/dashboard?id=oracle-devrel_oci-pac-opa)

## Introduction
This is a sample solution using [Open Policy Agent](https://openpolicyagent.org) (OPA) to validate Terraform proposed changes (plans) against a predetermined policy (defined in OPA) that is built for OCI resources.

## Solution
[Open Policy Agent](https://openpolicyagent.org) (OPA) is a great solution for this challenge.  OPA evaluates JSON (not HCL/HCL2), which yields itself to being really flexible/powerful.  Whether querying JSON output from Terraform or JSON data returned from calling the OCI API directly, OPA is pretty versatile.

There are two separate and distinct solutions provided:

* OCI Terraform Validation
* OCI API Body Validation

Each of these use-cases are discussed in greater detail below.  Before that, let's look at the high-level advantages/disadvantages (largely applicable to both solutions).

### Advantages
* Flexible deployment model - can run as API service, container or binary exec on instance
* Backed by Cloud Native Computing Foundation project, which means it'll hopefully be around for awhile
* Powerful rules engine (Rego) which allows for creation of simple and complex validation rules
* Built-in testing framework

### Disadvantages
* Rego is powerful, but also a bit complex and unnatural (initial ramp might be steep)

## Getting Started
Each solution has specific use-cases and nuances to running, so please look at the [OCI Terraform Validation README](./oci_terraform/README.md) and/or at the [OCI API Body Validation README](./oci_api/README.md) for more information (specific to each use-case).

### Interactive console
This is largely universal to both solutions.  To get to an interactive OPA console:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/input_tfplan.json,target=/input.json \
  openpolicyagent/opa:0.23.2 run repl.input:input.json
```

Change `input_tfplan.json` to whatever input JSON filename you'd like to use.

Here's an example of what might be done to interactively troubleshoot a policy:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/oci_policy.rego,target=/policy.rego \
  --mount type=bind,readonly,source="$(pwd)"/example/oci_vars-pass.rego,target=/vars.rego \
  openpolicyagent/opa:0.23.2 run vars.rego policy.rego
```

This will effectively open up an interactive console with the policy and variables prepopulated, allowing you to troubleshoot scenarios.  Don't forget to change to the correct package!

```
> package oci.tf_analysis
```

Here's an example of feeding some data in:

```
> test_input
{
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "oci_core_security_list.test_acl",
          "mode": "managed",
          "name": "test_acl",
          "provider_name": "oci.phx",
          "schema_version": 0,
          "type": "oci_core_security_list",
          "values": {
            "compartment_id": "ocid1.compartment.oc1..abc123",
            "display_name": "test_acl",
            "ingress_security_rules": [
              {
                "icmp_options": [],
                "protocol": "17",
                "source": "10.0.4.3/32",
                "source_type": "CIDR_BLOCK",
                "stateless": true,
                "tcp_options": [],
                "udp_options": [
                  {
                    "max": 123,
                    "min": 123,
                    "source_port_range": [
                      {
                        "max": 123,
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
> auth_errors with input as test_input
[
  "ERROR - The following Security List ingress rules are not allowed:\n\n{\"icmp_options\": [], \"protocol\": \"17\", \"source\": \"10.0.4.3/32\", \"source_type\": \"CIDR_BLOCK\", \"stateless\": true, \"tcp_options\": [], \"udp_options\": [{\"max\": 123, \"min\": 123, \"source_port_range\": [{\"max\": 123, \"min\": 123}]}]}."
]
>
```

Unfortunately `trace()` doesn't appear to work within unit tests, so this can be a helpful way of getting the exact data returned for a given scenario (especially if you're matching against exact return values as some of the unit tests do, such as looking at the error message returned).

Lastly, here's an idea if you'd like to interactively debug the JSON in a file:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/oci_policy.rego,target=/policy.rego \
  --mount type=bind,readonly,source="$(pwd)"/example/oci_vars-pass.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/example/tfplan.json,target=/input.json \
  openpolicyagent/opa:0.23.2 run vars.rego policy.rego repl.input:input.json
```

### Prerequisites
* Docker Desktop installed and available
  * `docker pull openpolicyagent/opa:latest` to download the OPA container
  * Better yet, be explicit on the version pulled: `docker pull openpolicyagent/opa:0.23.2`
* MacOS/Linux paths are used in this example (Windows users might need to change the path format)
* Git repo is cloned locally

#### Open Policy Agent Version
This solution is compatible with OPA v0.23.2.  This solution (or variations of it) have been used with older versions (back to OPA v0.15.0), though it's typically best to use the latest compatible version.

## Notes/Issues
There's always room for improvement!  Since this is just an example, it'll require you to adapt it to your specific needs and use-case(s).  Please file an issue for any suggested improvement.

## URLs
* https://www.openpolicyagent.org/
* https://www.openpolicyagent.org/docs/latest/ (and all other terrific documentation in the project)

## Contributing
This project is open source.  Please submit your contributions by forking this repository and submitting a pull request!  Oracle appreciates any contributions that are made by the open source community.

## License
Copyright (c) 2021 Oracle and/or its affiliates.

Licensed under the Universal Permissive License (UPL), Version 1.0.

See [LICENSE](LICENSE) for more details.
