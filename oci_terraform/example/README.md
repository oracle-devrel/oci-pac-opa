# Terraform JSON Validation - Examples

## Introduction

Here are a few examples (a passing and failing scenario given) so you can get an idea of the format of variables and a sample (sanitized) JSON file (generated from `terraform show` as described elsewhere in the documentation).

## Running

#### Simple pass/fail output

To see a passing scenario:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/tfplan.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-pass.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.tf_analysis.authz"
```

Likewise, to see a failing scenario:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/tfplan.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-fail.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.tf_analysis.authz"
```

#### Detailed errors output

To see what it looks like when things are all passing:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/tfplan.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-pass.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.tf_analysis.auth_errors"
```

And likewise, to see many validation failures:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/tfplan.json,target=/input.json \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-fail.rego,target=/vars.rego \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy.rego,target=/policy.rego \
  openpolicyagent/opa:0.23.2 eval --fail --format pretty --data policy.rego --data vars.rego --input input.json "data.oci.tf_analysis.auth_errors"
```

## Files
### `oci_vars-fail.rego`

These sample variables result in failed validation of the `tfplan.json` file.

### `oci_vars-pass.rego`

These sample variables result in passing validation of the `tfplan.json` file.

## `tfplan.json`

This is a sample, sanitized TF plan output that can be used to try out the example scenario (along with `oci_vars-pass.rego` and `oci_vars-fail.rego`, depending if you'd like to see a passed or failed validation).  This isn't useful beyond just allowing you to quickly see this solution at work, as it's been modified (sanitized).

## License

Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.

Licensed under the Universal Permissive License 1.0 or Apache License 2.0.

See [LICENSE](LICENSE) for more details.
