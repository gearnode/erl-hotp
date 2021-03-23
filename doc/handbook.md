# Introduction
This document contains development notes about the `hotp` library.

# Versioning
The following `hotp` versions are available:
- `0.y.z` unstable versions.
- `x.y.z` stable versions: `hotp` will maintain reasonable backward
  compatibility, deprecating features before removing them.
- Experimental untagged versions.

Developers who use unstable or experimental versions are responsible for
updating their application when `hotp` is modified. Note that
unstable versions can be modified without backward compatibility at any
time.

# Modules
## `hotp`
The HOTP implementation is based on the [RFC
4226](https://tools.ietf.org/html/rfc4226).

### `generate/2`
Generate an `HOTP` password.

Same as `generate(<<"secret">>, 0, #{})`.

### `generate/3`
Generate an `HOTP` password.

The following options are supported:

| Name      | Type    | Description                                       | Default |
|-----------|---------|---------------------------------------------------|---------|
| size      | integer | The number of digits in a password.               | 6       |
| algorithm | atom    | The crypto algorithm use to generate the password | sha     |


Example:
```erlang
hotp:generate(<<"secret">>, 1, #{size => 8}).
```

### `new_validator/1`
Returns a validator state that can be used by `validate/2` to validate
the `HOTP` password.

Same as `new_validator(<<"secret">>, #{})`.

### `new_validator/2`
Returns a validator state that can be used by `validate/2` to validate
the `HOTP` password.

The following options are supported:

| Name       | Type    | Description                                   | Default |
|------------|---------|-----------------------------------------------|---------|
| counter    | integer | The initial counter value.                    | 0       |
| size       | integer | The number of digits in a password.           | 6       |
| look_ahead | integer | The number of next counters to check validity | 5       |

Example:
```erlang
ValidatorState = hotp:new_validator(<<"secret">>, #{size => 8}).
```

### `validate/2`
Validates a `HOTP` password given a validator state.

Example:
```erlang
ValidatorState = hotp:new_validator(<<"secret">>),
{valid, NewValidatorState} = hotp:validate(ValidatorState, 533881).
```

## `totp`
The TOTP implementation is based on the [RFC
6238](https://tools.ietf.org/html/rfc6238).

### `generate/1`
Generate an `TOTP` password.

Same as `generate(<<"secret">>, #{})`.

### `generate/2`
Generate an `TOTP` password.

The following options are supported:

| Name         | Type    | Description                                       | Default |
|--------------|---------|---------------------------------------------------|---------|
| size         | integer | The number of digits in a password.               | 6       |
| algorithm    | atom    | The crypto algorithm use to generate the password | sha     |
| step         | integer | The time step in seconds                          | 30      |
| initial_time | integer | The Unix time to start counting time steps        | 0       |
| current_time | integer | TODO                                              | Now()   |

Example:
```erlang
hotp:generate(<<"secret">>, #{algorithm => sha512}).
```
