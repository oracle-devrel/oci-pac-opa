# Terraform JSON Validation - Unit Tests

## Files

### `oci_test.rego`

Here are where the unit tests are defined.  It's a good idea to have rules that test both approve and reject actions, to ensure that the policy behavior is what is expected.

There are two larger JSON definitions (invalid_tfplan and valid_tfplan) which are used primarily in the tests.

A few tests provide JSON input specific to the test (for instance, testing the Security List rule validation by providing a bad value for the port in one test, another test using a bad value for the IP, etc).  This allows us to focus on specific aspects of a rule that evaluates multiple attributes to give a go/no-go decision.

This is to be used with the `oci_policy.rego` policy.  It also is used with `dyn_acls.rego`.

### `oci_security_list_test.rego`

Security List specific unit tests reside here.  Because they are so large, it made sense to break them out into their own file.

This is to be used with the `oci_policy.rego` policy and the `oci_vars-test.rego` variables file.

## Running

To get a basic pass/fail:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy.rego,target=/tmp/policy.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_test.rego,target=/tmp/oci_test.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_security_list_test.rego,target=/tmp/oci_security_list_test.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-test.rego,target=/tmp/vars.rego \
  openpolicyagent/opa:0.23.2 test /tmp --format pretty
```

An additional parameter (-v) may be provided, which will provide more verbose output (it will show the status for each test, rather than just the summary of the tests that passed and the total number of tests).

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy.rego,target=/tmp/policy.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_test.rego,target=/tmp/oci_test.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_security_list_test.rego,target=/tmp/oci_security_list_test.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-test.rego,target=/tmp/vars.rego \
  openpolicyagent/opa:0.23.2 test /tmp --format pretty -v
```

To see coverage:

```
docker run -it \
  --mount type=bind,readonly,source="$(pwd)"/../oci_policy.rego,target=/tmp/policy.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_test.rego,target=/tmp/oci_test.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_security_list_test.rego,target=/tmp/oci_security_list_test.rego \
  --mount type=bind,readonly,source="$(pwd)"/oci_vars-test.rego,target=/tmp/vars.rego \
  openpolicyagent/opa:0.23.2 test --coverage /tmp
```
