# OCI API JSON Validation - Examples

## Introduction
Here are a few examples (a passing and failing scenario given) so you can get an idea of the format of variables and sample (sanitized) JSON files that represent what might be received (or sent) to/from the OCI API.  See https://docs.cloud.oracle.com/en-us/iaas/api for a more details around the OCI API.

## Running
For each of these examples, both a single resource as well as an array of multiple resources is provided.  This is designed to simulate GET/CREATE/UPDATE on a single resource versus a LIST operation which will return a list (array) of multiple resources.

### Subnets

#### Simple pass/fail output
To see a passing scenario (single):

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/subnets.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-pass.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy_subnet.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.api_analysis.authz"
```

To see a passing scenario (multiple):

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/subnets.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-pass.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy_subnet.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.api_analysis.authz"
```

Likewise, to see a failing scenario:

```
  docker run -it \
    --mount type=bind,readonly,source="$(pwd)"/subnets.json,target=/input.json \
    --mount type=bind,readonly,source="$(pwd)"/oci_vars-fail.rego,target=/vars.rego \
    --mount type=bind,readonly,source="$(pwd)"/../oci_policy_subnet.rego,target=/policy.rego \
    openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.api_analysis.authz"
```

#### Detailed errors output
To see what it looks like when things are all passing:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/subnets.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-pass.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy_subnet.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.api_analysis.auth_errors"
```

And likewise, to see many validation failures:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/subnets.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-fail.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy_subnet.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.api_analysis.auth_errors"
```

Or you can use it with a single subnet:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/subnet.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-fail.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy_subnet.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.api_analysis.auth_errors"
```

## Files
### `oci_vars-fail.rego`
These sample variables result in failed validation of the `subnets.json` file.

### `oci_vars-pass.rego`
These sample variables result in passing validation of the `subnets.json` file.

### `subnets.json`
This is a sample, sanitized set of OCI Subnets that can be used to try out the example scenario (along with `oci_vars-pass.rego` and `oci_vars-fail.rego`, depending if you'd like to see a passed or failed validation).  This isn't useful beyond just allowing you to quickly see this solution at work, as it's been modified (sanitized and shortened).

### `subnet.json`
This is a sample, sanitized single OCI Subnet that can be used to try out the example scenario (along with `oci_vars-pass.rego` and `oci_vars-fail.rego`, depending if you'd like to see a passed or failed validation).  This isn't useful beyond just allowing you to quickly see this solution at work, as it's been modified (sanitized and shortened).

## License
Copyright (c) 2021 Oracle and/or its affiliates.

Licensed under the Universal Permissive License (UPL), Version 1.0.

See [LICENSE](../../LICENSE) for more details.
