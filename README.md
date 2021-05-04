<p align="center">
<img src="mascot/banner.png" alt="db-auth-gateway" title="db-auth-gateway" />
</p>

# db-auth-gateway

An authentication proxy for Google Cloud managed databases. Based on the ideas
of [cloudsql-proxy](https://github.com/GoogleCloudPlatform/cloudsql-proxy) but
intended to be run as a standalone network accessible service rather than a 
sidecar.

We've been using `cloudsql-proxy` for several years now to power our 
[db-operator](https://github.com/kloeckner-i/db-operator) project. It has been 
for the most part reliable but key differences between how we deploy it and 
Google's reference architecture have led to production issues. 

We developed `db-auth-gateway` to address these issues and add a variety of wish 
list features such as improved observability, and testing.

## Features

* Connection draining during shutdown to support zero downtime deployments and 
load balancing.
* Prometheus metrics support for improved observability.
* Full testsuite including realistic Google service mocks.
* Simplified modern code base.

## Quickstart

Use `docker-compose` to start a local PostgreSQL instance, and Google API mock:

```shell script
make start_mock
```

Then you can then run `db-auth-gateway` locally with:

```shell script
db-auth-gateway --api-endpoint=http://localhost:8080 --credential-file=DISABLED \
--instance=my-project:my-region:my-database
```

`db-auth-gateway` will listen on port 5432 (by default) for SQL connections.

```shell script
PGPASSWORD=mysecretpassword psql -h localhost -p 5432 -d postgres postgres
```

### Flags

`db-auth-gateway` has a variety of command line flags for configuring its behavior:

| Flag | Default | Description |
|:---|:---:|:---|
| --credential-file | | JSON file containing the Google Cloud credentials |
| --instance | | Fully qualified database instance to connect to (project:region:name) |
| --listen | :5432 | Address and port to listen on |
| --remote-port | 3307 | Port to connect to the remote server on |
| --max-connections | 0 | The maximum number of active connections. Defaults to 0 (unlimited) |
| --min-refresh-interval | 1m | The minimum amount of time to wait between API calls |
| --periodic-refresh-interval | 5m | Configuration is eagerly refreshed on a schedule. This is the nominal period between API calls. |
| --api-endpoint | | If specified the URL to use for API calls |

## Development

### Prerequisites

* [Go 1.15+](https://golang.org/dl/)
* GNU Make
* [golangci-lint v1.30+](https://golangci-lint.run/usage/install/)
* Additional Go tools:
    * [golint](https://github.com/golang/lint)
    * [gofumpt](https://github.com/mvdan/gofumpt)
    * [gofumports](https://github.com/mvdan/gofumpt)
    * [gci](https://github.com/daixiang0/gci)

### Build

To build `db-auth-gateway`, simply run make without any arguments.

The resulting binary will be written to: `./target/db-auth-gateway`.

```shell script
make
```

### Test

Before committing any code you should always lint and test your changes.

#### Code Linting

```shell script
make lint
```

#### Running the Tests

First start the Google API mock using `docker-compose`:

```shell script
make start_mock
```

Then run the tests:

```shell script
make test
```

### End to End Testing

You run the end to end tests with:

```shell script
make e2e
```

The tests will start a local instance of `db-auth-gateway` and verify it is able
to connect to and query the Postgres database, and Google API mock.

## Acknowledgements

1. [The Go Gopher](https://blog.golang.org/gopher) by [Renee French](http://reneefrench.blogspot.com/), licensed under the [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/).
1. https://github.com/GoogleCloudPlatform/cloudsql-proxy
1. https://github.com/jbenet/go-context
