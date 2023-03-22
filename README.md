# simple-oidc-client

A simple webserver that serves as an oidc client. It authenticates to an Identity Provider using [OpenID Connect](https://openid.net/connect/) and returns the JWT token that it gets from the Idp. This is mainly written to get some experience with Rust programming (so don't expect great code quality).

Only the authorization code flow is implemented (with PKCE), using the examples from the [Rust openidconnect](https://docs.rs/openidconnect/latest/openidconnect/) crate.

## Running it

First, register and oidc client in your Idp. This will provide you a clientId and client secret. Use `http://localhost:3000/oidc/callback` as redirect url (or any other listen port if you change that config var).

After you have registered your client, make an env file containing the following environment variables and source it:

```
export APP_CLIENT_SECRET="my-client-secret"
export APP_CLIENT_ID="my-client-id"
export APP_ISSUER_URL="https://my-idp-issuer-url"   # without the '/.well-known' suffix
export APP_PORT=3000                                # Optional, defaults to 3000
export APP_SCOPES="openid my-scopes"                # Optional, defaults to 'openid'
export APP_SESSION_SECRET="my-secret"               # At least 64 chars, optional, will be randomly generated if not provided
```

After this, you can build and run the application:

```
$ cargo build
$ source ./env
$ cargo run
```

It will validate your configuration on startup, and it will panic with an error message if the config is invalid. If everything is valid and OIDC discovery succeeds, it will print 'Found issuer!'. After that it starts listening for requests and you can visit [http://localhost:3000](http://localhost:3000) to start the oidc flow.
