# Rokwire Building Block SDK for Go

rokwire-building-block-sdk-go is the official Rokwire Building Block SDK for Golang. This SDK enables easy communication with the Rokwire Building Blocks and provides commonly used utilities.

## Prerequisites

* Go v1.24+
* MongoDB v4.4+

## Installation

To install this package or upgrade to the latest version, use `go get`:

```bash
go get -u github.com/rokwire/rokwire-building-block-sdk-go
```

## Upgrading

### Staying up to date

To update rokwire-building-block-sdk-go to the latest version, use `go get -u github.com/rokwire/rokwire-building-block-sdk-go`.

### Migration steps

Follow the steps below to upgrade to the associated version of this library. Note that the steps for each version are cumulative, so if you are attempting to upgrade by several versions, be sure to make the changes described for each version between your current version and the latest.

#### Migrating from core-auth-library and logging-library
This SDK has incorporated all of the components included in the following libraries. These libraries have been deprecated and continuing support for the features they provided will be handled only on this SDK going forward.

- https://github.com/rokwire/core-auth-library-go
- https://github.com/rokwire/logging-library-go

Although this SDK includes all of the components of these libraries, the directory structure and naming has been changed to better fit into the context of this SDK. This repository includes an [import migration script](tools/migrate_imports.py) as a tool to help apply the necessary changes to imports and references throughout your codebase to match the new structure. To use this script, ensure you have Python installed and proceed to the instructions below.

To migrate any services that make use of the libraries mentioned above to the SDK, please use the following steps:

##### Using the import migration script

1. Ensure you are using the latest versions of `core-auth-library-go/v3` and/or `logging-library-go/v2`. If not, follow the migration guides in those libraries to upgrade before continuing.
2. Update the `go.mod` file in your service to remove the dependencies on `core-auth-library-go` and `logging-library-go`
3. Install the SDK, following the instructions under [Installation](#installation)
4. Clone this repository to your machine `git clone git@github.com:rokwire/rokwire-building-block-sdk-go.git`
5. Open a terminal in the root directory of your service repository
6. Run the [import migration script](tools/migrate_imports.py) `python <path-to-cloned-sdk-repo>/tools/migrate_imports.py`
7. Run `go mod tidy` and `go mod vendor`
8. Fix any package/naming conflicts
9. Run `make` to ensure that there are no errors

##### Manual import migration
If you cannot or prefer not to use the [import migration script](tools/migrate_imports.py), you can manually apply the necessary changes to the import paths and references. To do so, we recommend using the "find and replace" feature of your IDE to apply the following changes:

For the auth library, find and replace the following imports:
- `github.com/rokwire/core-auth-library-go/v3/tokenauth` -> `github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/tokenauth`,
- `github.com/rokwire/core-auth-library-go/v3/webauth` -> `github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/webauth`
- `github.com/rokwire/core-auth-library-go/v3/keys` -> `github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/keys`
- `github.com/rokwire/core-auth-library-go/v3/sigauth` -> `github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/sigauth`
- `github.com/rokwire/core-auth-library-go/v3/authservice` -> `github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth`
- `github.com/rokwire/core-auth-library-go/v3/authutils` -> `github.com/rokwire/rokwire-building-block-sdk-go/utils/rokwireutils`
- `github.com/rokwire/core-auth-library-go/v3/coreservice` -> `github.com/rokwire/rokwire-building-block-sdk-go/services/core`
- `github.com/rokwire/core-auth-library-go/v3/envloader` -> `github.com/rokwire/rokwire-building-block-sdk-go/utils/envloader`
- `github.com/rokwire/core-auth-library-go/v3/authorization` -> `github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/authorization`
- Dockerfile
  - `/app/vendor/github.com/rokwire/core-auth-library-go/v3/authorization` -> `/app/vendor/github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/authorization`

You will also need to find and replace the following references for the new imports:
- `authutils.` -> `rokwireutils.`,
- `authservice.AuthService` -> `auth.Service`,
- `authservice.` -> `auth.`,
- `coreservice.` -> `core.`,

For the logging library, find and replace the following imports:
- `github.com/rokwire/logging-library-go/v2/errors` -> `github.com/rokwire/rokwire-building-block-sdk-go/utils/errors`
- `github.com/rokwire/logging-library-go/v2/logutils` -> `github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils`
- `github.com/rokwire/logging-library-go/v2/logs` -> `github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs`



#### Unreleased

#### [1.0.2](https://github.com/rokwire/rokwire-building-block-sdk-go/compare/v1.0.1...v1.0.2)

##### Breaking changes

###### web

* `Adapter[T common.Storage].RegisterHandlerFunc` has been renamed to `Adapter[T common.Storage].RegisterGeneratedHandlerFunc`.

#### [1.0.1](https://github.com/rokwire/rokwire-building-block-sdk-go/compare/v1.0.0...v1.0.1)

##### Breaking changes

###### keys

* `PrivKey.Sign` now takes `message string` as an argument instead of `message []byte`.
* `PubKey.Verify` now takes `message string` as an argument instead of `message []byte`.

###### sigauth

* `SignatureAuth.Sign` now takes `message string` as an argument instead of `message []byte`.
* `SignatureAuth.CheckServiceSignature` now takes `message string` as an argument instead of `message []byte`.
* `SignatureAuth.CheckSignature` now takes `message string` as an argument instead of `message []byte`.
* `SignatureAuth.LegacyCheckSignature` now takes `message string` as an argument instead of `message []byte`.

###### tokenauth

* `Claims` now uses `jwt.RegisteredClaims` (github.com/golang-jwt/jwt/v5) as an embedded struct instead of `jwt.StandardClaims` (github.com/golang-jwt/jwt v3).

## Packages

This library contains several packages:

### `auth`

The `auth` package provides the `Service` type which contains the configurations to locate and communicate with the ROKWIRE Auth Service. The other packages in this library depend on the `Service` object, or other objects which depend on it, to handle any necessary communication with this central Auth Service.

This package also provides the `ServiceRegLoader`, `ServiceRegManager`, `ServiceAccountLoader`, and `ServiceAccountManager` types.

The `ServiceRegManager` type uses the configuration defined in an `Service` instance and a `ServiceRegLoader` instance to load, store, and manage service registration data (`ServiceReg` type).

The `ServiceAccountManager` type uses the configuration defined in an `Service` and a `ServiceAccountLoader` instance to load, storage, and manage service account data (e.g., access tokens, with the `AccessToken` type).

Import the `rokwire-building-block-sdk-go/services/core/auth` package into your code using this template:

```go
package yours

import (
  ...

  "github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
)

func main() {
    // Instantiate an auth.Service to maintain basic auth data
    authService := auth.Service{
        ServiceID:   "sample",
        ServiceHost: "https://rokwire.illinois.edu/sample",
        FirstParty:  true,
        AuthBaseURL: "https://rokwire.illinois.edu/auth",
    }

    // Instantiate a remote ServiceRegLoader to load auth service registration record from auth service
    serviceRegLoader, err := auth.NewRemoteServiceRegLoader(&authService, []string{"auth"})
    if err != nil {
        log.Fatalf("Error initializing remote service registration loader: %v", err)
    }

    // Instantiate a ServiceRegManager to manage the service registration data loaded by serviceRegLoader
    serviceRegManager, err := auth.NewServiceRegManager(&authService, serviceRegLoader)
    if err != nil {
        log.Fatalf("Error initializing service registration manager: %v", err)
    }

    // Instantiate a remote ServiceAccountLoader to load auth service account data from auth service
    staticTokenAuth := auth.StaticTokenServiceAuth{ServiceToken: "sampleToken"}
    serviceAccountLoader, err := auth.NewRemoteServiceAccountLoader(&authService, "sampleAccountID", staticTokenAuth)
    if err != nil {
        log.Fatalf("Error initializing remote service account loader: %v", err)
    }

    // Instantiate a remote ServiceAccountManager to manage service account-related data
    serviceAccountManager, err := auth.NewServiceAccountManager(&authService, serviceAccountLoader)
    if err != nil {
        log.Fatalf("Error initializing service account manager: %v", err)
    }

    ...
}
```

### `core`

The `core` package provides the `Service` type which contains the configurations and helper functions to utilize certain functions implemented by the ROKWIRE Core Building Block. One example of these functions is getting the IDs of accounts deleted within a set amount of time ago.

### `tokenauth`

The `tokenauth` package provides the `TokenAuth` type which exposes the interface to validate and authorize auth tokens generated by the ROKWIRE Auth Service.

### `webauth`

The `webauth` package provides the utility functions that are useful when handling web applications. This includes setting cookies and verifying both cookies and headers to secure these web applications.

### `sigauth`

The `sigauth` package provides the `SignatureAuth` type which exposes the interface to sign and verify HTTP requests to communicate securely between services within the ROKWIRE ecosystem.

### `authorization`

The `authorization` package provides a generic `Authorization` interface and a specific `CasbinAuthorization` and `CasbinScopeAuthorization` implementation of this interface that can be used with the `TokenAuth` object. There are two standard Casbin models that can be found in `authorization/authorization_model_string.conf` and `authorization/authorization_model_scope.conf` that can be used with each of these types respectively. You can also define your own model if neither of these fits the use case.

### `envloader`

The `envloader` package provides the `EnvLoader` interface which facilitates the loading of environment variables from various environments. Two standard implementations have been provided: `LocalEnvLoader` and `AWSSecretsManagerEnvLoader`. The `LocalEnvLoader` loads all variables from the environment variables set on the local machine, while the `AWSSecretsManagerEnvLoader` will load them from an AWS SecretsManager Secret.

#### `AWSSecretsManagerEnvLoader`

When using the `AWSSecretsManagerEnvLoader`, two environment variables must be set on the local machine to configure the specific secret to be accessed. The underlying infrastructure must also have the appropriate AWS permissions/roles to access the specied secret.

Environment Variables:
Name|Description
---|---
APP_SECRET_ARN | The AWS ARN of the AWS SecretsManager Secret to be accessed
AWS_REGION | The AWS region of the AWS SecretsManager Secret to be accessed

The `NewEnvLoader()` function can be used to automatically select and create the correct `EnvLoader` implementation object. If the two environment variables mentioned above are set, an `AWSSecretsManagerEnvLoader` will be returned, otherwise a `LocalEnvLoader` will be returned.

### `rokwireutils`

The `rokwireutils` package contains constants and standard utilities shared by the other packages.

### `keys`

The `keys` package contains constants and generalized public key and private key wrapper types that are used by other packaages.

### `logs`

The `logs` package provides the `Logger` and `Log` types. The `Logger` object provides the base configurations for the entire application, while the `Log` object carries state related to a specific request.

Import the `rokwire-building-block-sdk-go/utils/logging/logs` package into your code using this template:

```go
package yours

import (
  ...

  "github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

func main() {
    var logger = logs.NewLogger("example", nil)
    logger.SetLevel(logs.Debug)

    ...
}
```

### `errors`

The `errors` package provides the `Error` type which expands upon the functionality provided by the typical `error` primitive provided by Golang. For example, additional context such as a trace of wrapped errors is automatically maintained when using the `Wrap` functions. Various components of this chain can then be accessed through the convenience functions provided by this package.

### `logutils`

The `logutils` package contains constants and standard utilities shared by the `logs` and `errors` packages.

## Error Wrappers

There are several convenience functions to help standardize the error generation process.

```go
//NewError returns an error containing the provided message
func NewError(message string) error

//NewErrorf returns an error containing the formatted message
func NewErrorf(message string, args ...interface{}) error 

//WrapErrorf returns an error containing the provided message and error
func WrapError(message string, err error) error 

//WrapErrorf returns an error containing the formatted message and provided error
func WrapErrorf(format string, err error, args ...interface{}) error
```

These functions should be used in place of `fmt.Errorf` and `errors.New`. They provide several key benefits.

1. **Consistent formatting:** When using these functions, the provided messages will be formatted in one standard format. This will make it easier to read and follow logs throughout and across services.
2. **Context:** These functions will all automatically include information about the function that is generating the error to help trace the path of the call when the errors are logged at a higher level.
3. **Convenience:** This provides on central package that can be imported to create errors. It also provides convenience functions to wrap existing errors with more context which should be a common practice with our logging approach.

## Logging Helpers

There are several convenience functions that will help perform logging in common situations.

The `LogError` function can be used to log a message along with an existing `error` object.

```go
//LogError prints the log at error level with given message and error
//    Returns combined error message as string
func (l *Log) LogError(message string, err error) string
```

The following functions manage logging, generating, and sending HTTP responses conveniently.

```go
// SendHTTPResponse finalizes response data and sends the content of an HTTPResponse to the provided http.ResponseWriter
func (l *Log) SendHTTPResponse(w http.ResponseWriter, response HTTPResponse)



// HTTPResponseSuccess generates an HTTPResponse with the message "Success" with status code 200, sets standard headers, and stores the status to the log context
func (l *Log) HTTPResponseSuccess() HTTPResponse

// HTTPResponseSuccess generates an HTTPResponse with the provided success message with status code 200, sets standard headers, and stores the message and status to the log context
func (l *Log) HTTPResponseSuccessMessage(message string) HTTPResponse

// HTTPResponseSuccess generates an HTTPResponse with the provided success message and status code, sets standard headers, and stores the message and status to the log context
func (l *Log) HTTPResponseSuccessStatusMessage(message string, code int) HTTPResponse

// HTTPResponseSuccessJSON generates an HTTPResponse with the provided JSON as the HTTP response body with status code 200, sets standard headers,
// and stores the status to the log context
func (l *Log) HTTPResponseSuccessJSON(json []byte) HTTPResponse

// HTTPResponseSuccessStatusJSON generates an HTTPResponse with the provided JSON as the HTTP response body and status code, sets standard headers,
// and stores the status to the log context
func (l *Log) HTTPResponseSuccessStatusJSON(json []byte, code int) HTTPResponse

// HTTPResponseSuccessBytes generates an HTTPResponse with the provided bytes as the HTTP response body with status code 200,
// sets standard headers, and stores the status to the log context
func (l *Log) HTTPResponseSuccessBytes(bytes []byte, contentType string) HTTPResponse 

// HTTPResponseSuccessBytes generates an HTTPResponse with the provided bytes as the HTTP response body and status code,
// sets standard headers, and stores the status to the log context
func (l *Log) HTTPResponseSuccessStatusBytes(bytes []byte, contentType string, code int) HTTPResponse

// HTTPResponseError logs the provided message and error and generates an HTTPResponse
func (l *Log) HTTPResponseError(message string, err error, code int, showDetails bool) HTTPResponse
```

## Message Templates

This library includes two standardized templates/grammars for messages, as well as a dictionary of commonly used terms. The intention of providing this is to help keep the logs very consistent and easy to interpret when adding new functionality with new logs.

### Data Template

The "data" message template can be used to describe common statuses of a specified data element.

**Pattern:** `{data status} {type}: {args}`
**Example:** `Invalid query param: id=test_id`

### Action Template

The "action" message template can be used to describe common actions performed on a specified data type.

**Pattern:** `{action status} {action} {type} for {args}`
**Example:** `Error marshalling organization for id=test_id`

### Message Template Parameters

Below are definitions and examples for the template parameters references above.

#### Data Status

Data statuses describe the data element and are represented by the `logDataStatus` type.

- `StatusValid` ("Valid"), `StatusFound` ("Found"), `StatusInvalid` ("Invalid"), `MissingStatus` ("Missing")

#### Action Status

Action statuses describe the the action and are represented by the `logActionStatus` type.

- `StatusSuccess` ("Success"), `StatusError` ("Error")

#### Action

Actions represent the action taken on the data element and are represented by the `LogAction` type.

- Eg. `ActionFind` ("finding"), `ActionMarshal` ("marshalling"), `ActionInitialize` ("initializing"), `ActionSend` ("sending")... etc.

Many common actions are defined in the logging library and these should be used when possible to maintain standardization. If you cannot construct an accurate message with the provided defined actions, you may provide your own action verb (ending in -ing) to describe the situation.

#### Type

Types are representations of the data type that the status applies to represented by the `LogData` type.

- Eg. `TypeQueryParam` ("query param"), `TypeRequest` ("request"), "organization", "user"... etc

There are several common types that will be reused across applications defined in the logging library, however each application should define types to represent various models specific to its context.

#### Args

Args are arbitrary parameters which can be included to provide additional information about the data or action represented by the `logArgs` interface. There are three types of `logArgs`: `FieldArgs` (`map[string]string`), `ListArgs` (`[]string`), and `StringArgs` (`string`). Most commonly, these will be variable name and value pairs (`FieldArgs`).

- Eg. `FieldArgs{"id": "test_id", "name": "test_name"}`, `ListArgs{"id", "name"}`, `StringArgs("id")`... etc

### Message Template Helper Functions

There are several convenience functions to help log or create an error from these templates.

**Note:** `nil` "args" params are ok

Messages:

```go
// MessageData generates a message string for a data element
func MessageData(status MessageDataStatus, dataType MessageDataType, args MessageArgs) string

// MessageAction generates a message string for an action
func MessageAction(status MessageActionStatus, action MessageActionType, dataType MessageDataType, args MessageArgs) string 

// MessageActionError generates a message string for an action that resulted in an error
func MessageActionError(action MessageActionType, dataType MessageDataType, args MessageArgs) string

// MessageActionSuccess generates a message string for an action that succeeded
func MessageActionSuccess(action MessageActionType, dataType MessageDataType, args MessageArgs) string
```

Errors:

```go
//DataError generates an error for a data element
func DataError(status logDataStatus, dataType LogData, args logArgs) error

//WrapDataError wraps an error for a data element
func WrapDataError(status logDataStatus, dataType LogData, args logArgs, err error) error

//ActionError generates an error for an action
func ActionError(action LogAction, dataType LogData, args logArgs) error

//WrapActionError wraps an error for an action
func WrapActionError(action LogAction, dataType LogData, args logArgs, err error) error
```

Responses:

```go
// HTTPResponseSuccessAction generates an HTTPResponse with the provided success action message, sets standard headers, and stores the message to the log context with status code 200
func (l *Log) HTTPResponseSuccessAction(action logutils.MessageActionType, dataType logutils.MessageDataType, args logutils.MessageArgs) HTTPResponse

// HTTPResponseSuccessStatusAction generates an HTTPResponse with the provided success action message and status code, sets standard headers, and stores the message to the log context
func (l *Log) HTTPResponseSuccessStatusAction(action logutils.MessageActionType, dataType logutils.MessageDataType, args logutils.MessageArgs, code int) HTTPResponse

// HTTPResponseErrorAction logs an action message and error and generates an HTTPResponse
func (l *Log) HTTPResponseErrorAction(action logutils.MessageActionType, dataType logutils.MessageDataType, args logutils.MessageArgs, err error, code int, showDetails bool) HTTPResponse

// HTTPResponseErrorData logs a data message and error and generates an HTTPResponse
func (l *Log) HTTPResponseErrorData(status logutils.MessageDataStatus, dataType logutils.MessageDataType, args logutils.MessageArgs, err error, code int, showDetails bool) HTTPResponse
```

## Other Conventions

There are several recommended conventions for the use of this library:

### Internal functions do not write logs unless necessary

Internal functions (core, storage, auth...etc) should not log to the console in general. They should instead return an error to be logged at the API handler level. Using the error wrapping functions in this libarary will make sure that the relevant context is not lost along the way.

Exceptions to this rule include warnings, where it is important that a log is generated indicating that an error occurred, but it is not a critical error which prevented successful execution. When this happens the error should not be returned, so a `Warn` function should be called on the `Log` object with the relevant information. Debug logging statements are also an exception here, for example printing the contents of an object at a specific point to keep a record in the dev environment. Finally, on some occasions, `Info` logs can be printed in core functions to indicate that a specific action occurred... etc.

### Use the Log object whenever possible

When it is necessary to write to the logs, the `Log` object should be used over the `Logger` object (or any other logging library/package) whenever possible. `Log` objects contain additional information and ensure that any printed logs are properly associated with the request being handled. They also allow you to store context to be logged upon the success or failure of the request.

For example, if a non-critical issue occurs in a storage function and we want to log a warning without returning an error, the storage function should include a `*log.Log` in the function params. No `Logger` object should be stored and made available to internal functions outside of the initialization context.

Exceptions to this rule include initialization when there is no request being processed and therefore no `Log` object. Timer based functions are also in this category. In these cases the `Logger` should be used instead.

### Errors should almost always be wrapped at every level

When an error is received from a function call and returned, one of the error wrapping helpers should be used to provide additional context in a message. This also will ensure that the chain of function calls is preserved within the `Error` object.

To get started, take a look at `example/app.go`

## Usage

To get started, take a look at the `example/` directory.

## Contributing

If you would like to contribute to this project, please be sure to read the [Contributing Guidelines](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), and [Conventions](CONVENTIONS.md) before beginning.

### Secret Detection

This repository is configured with a [pre-commit](https://pre-commit.com/) hook that runs [Yelp's Detect Secrets](https://github.com/Yelp/detect-secrets). If you intend to contribute directly to this repository, you must install pre-commit on your local machine to ensure that no secrets are pushed accidentally.

```bash
# Install software 
$ git pull  # Pull in pre-commit configuration & baseline 
$ pip install pre-commit 
$ pre-commit install
```
