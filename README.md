# simple-oidc-client

A simple webserver that serves as an oidc client. It authenticates to an Identity Provider using [OpenID Connect](https://openid.net/connect/) and returns the JWT token that it gets from the Idp. This is mainly written to get some experience with Rust programming (so don't expect great code quality).

Only the authorization code flow is implemented (with PKCE), using the examples from the [Rust openidconnect](https://docs.rs/openidconnect/latest/openidconnect/) crate.

## Running it

First, register an oidc client in your Idp. This will provide you with a clientId. Use `http://localhost:3000/oidc/callback` as redirect url (or any other listen port if you change that config var).

### Choose how to authenticate to the Idp

You can choose to authenticate to the Idp with a client secret (the 'old' method) or with the [private\_key\_jwt grant](https://oauth.net/private-key-jwt/). For `private_key_jwt`, you need to generate an RSA key and certificate, which can be generated with the following command:

```
$ openssl req -x509 -days 365 -newkey rsa:2048 -keyout key-dev.pem -out cert-dev.pem -nodes -batch
```

### Configure your env file

After you have registered your client and secret, make an env file containing the following environment variables and source it:

```
export APP_CLIENT_ID="my-client-id"
export APP_CLIENT_SECRET="my-client-secret"               # If you want to use an OAuth client secret, or:
export APP_PRIVATE_JWT_CERT='-----BEGIN CERTIFICATE-----  # If you want to use private_key_jwt
export APP_PRIVATE_JWT_KEY='-----BEGIN PRIVATE KEY-----   # If you want to use private_key_jwt
export APP_ISSUER_URL="https://my-idp-issuer-url"         # without the '/.well-known' suffix
export APP_PORT=3000                                      # Optional, defaults to 3000
export APP_SCOPES="openid my-scopes"                      # Optional, defaults to 'openid'
export APP_SESSION_SECRET="my-secret"                     # At least 64 chars, optional, will be randomly generated if not provided
```

See the example-env.txt file for an example (especially configuring the RSA key/cert can by tricky with the newlines).

### Compile and run

After this, you can build and run the application:

```
$ cargo build
$ source ./env
$ cargo run
```

It will validate your configuration on startup, and it will panic with an error message if the config is invalid. If everything is valid and oidc discovery succeeds, it will print 'Found issuer!'. After that it starts listening for requests and you can visit [http://localhost:3000](http://localhost:3000) to start the oidc flow.
