# OpenID Provider for authenticating users with an eIDAS digital certificate

This project implements two different but related functionalities:

1. A minimalist OpenID Provider (OP) focused on only one thing: enable applications to authenticate users using their eIDAS certificate issued to them by a QTSP (Qualified Trust Service Provider). This project does not have to provide all the features that "normal" OPs provide.

2. A registration service that applications can use to onboard users with their eIDAS certificate. This service relies on the previous one to authenticate users with their eIDAS certificate.

The eIDAS certificate of the users is validated against the EU Trusted Lists (https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls), ensuring the association of the certificate with the real-world identity of the user, either as a natural person or as a natural person who is a legal representative of an organization. In both cases, the identity of the user has been validated by one of the more than 200 QTSPs in the EU, which are highly regulated entities. In the case of a legal representative, the identity of the organization has been validated by the issuer QTSP, together with the relationship of the user with the organization.

## Quick Start (Local Development)

To run the application locally with Docker:

### Prerequisites
1. Docker and Docker Compose installed
2. Add to `/etc/hosts`:
   ```bash
   127.0.0.1 certauth.localhost
   127.0.0.1 certsec.localhost
   127.0.0.1 onboard.localhost
   ```

### Setup and Run

```bash
# 1. Create test certificates
chmod +x create-test-cert.sh && ./create-test-cert.sh

# 2. (macOS) Install CA certificate to avoid browser warnings
chmod +x install-cert.sh && ./install-cert.sh

# 3. Import client certificate to your browser
# Import certs/client.p12 (password: test)

# 4. Start services
docker-compose up -d

# 5. Open browser
# Visit https://onboard.localhost and test the flow
```

### Local Development Features

When running with `PROFILE=local` (default):
- **Email verification bypass**: Codes displayed on screen, SMTP failures non-blocking
- **Certificate validation**: Self-signed certificates accepted with warnings
- **Test data**: Sample certificates with all required eIDAS fields

### Service URLs
- **Onboard** (user registration): https://onboard.localhost
- **CertAuth** (OpenID Provider): https://certauth.localhost  
- **CertSec** (mTLS authentication): https://certsec.localhost

### Complete Documentation
See [DOCKER_SETUP.md](DOCKER_SETUP.md) for detailed setup, troubleshooting, and configuration options.

## Deployment

The deployment of this project is very simple using Docker. With other infrastructure, it should be very simple to map into its requirements.

The project includes a Dockerfile which can be used to generate a Docker image. When creating a container instance, the folowing environment variables have to be provided.

- `PROFILE`: Optional. The profile to use. If you omit it, the default is `local`. The available profiles are `isbe-dev`, `isbe-pre`, `isbe-pro`.
- `SMTP_USERNAME`: The username for the SMTP server used to send emails to the end-users.
- `SMTP_PASSWORD`: The password for the SMTP server.
- `TSA_USER`: The username for the TSA (Timestamping Authority) server, used to timestamp the act of user acceptance of the terms of service.
- `TSA_PASSWORD`: The password for the TSA server.

The `PROFILE` environment variable is used to select the profile to use for a deployment in ISBE. The available profiles are `isbe-dev`, `isbe-pre` and `isbe-pro`. Selecting a profile will configure the application with the appropriate values for the target environment.

The other four environment variables are required for all profiles, and are not included in the profiles, given its sensitive nature. You should ask your systems administyrator for the appropriate values for your environment.

## Configuration Reference

The following environment variables can be used to override configuration values:

| Variable | Description | Default |
|----------|-------------|---------|
| `CERTAUTH_URL` | Base URL for the CertAuth service | Profile dependent |
| `CERTAUTH_PORT` | Port for CertAuth service | `8010` |
| `CERTSEC_URL` | URL for the mTLS CertSec service | Profile dependent |
| `CERTSEC_PORT` | Port for CertSec service | `8011` |
| `ONBOARD_URL` | URL for the Onboard service | Profile dependent |
| `ONBOARD_PORT` | Port for Onboard service | `8012` |
| `TSA_URL` | Timestamp Authority URL | `https://timestamp-service...` |
| `MANAGEMENT_URL` | Management Service URL | Profile dependent |
| `CERTAUTH_LOGS_NOCOLOR` | Set to "true" to disable log coloring | `false` |

## Observability

The CertAuth service exposes Prometheus metrics at the `/metrics` endpoint. 
These metrics are generated using `ansrivas/fiberprometheus/v2` and include standard Go runtime metrics as well as HTTP request metrics.

### Endpoint
`GET /metrics`

No authentication is currently required for this endpoint.

### Metric Labels
All HTTP metrics include the following common labels:
- `service`: "certauth" (The name of this service)
- `method`: HTTP method (e.g., "GET", "POST")
- `path`: The registered route path (e.g., "/health", "/oidc/authorize")
- `status`: HTTP status code (e.g., "200", "500")

### HTTP Metrics

#### `http_requests_total`
- **Type**: Counter
- **Description**: Total number of HTTP requests processed, partitioned by status code, method, and path.
- **Usage**: Use `rate()` to calculate requests per second (RPS).

#### `http_request_duration_seconds`
- **Type**: Histogram
- **Description**: The duration of HTTP requests in seconds.
- **Buckets**: Default buckets are used (def `[.005 .01 .025 .05 .1 .25 .5 1 2.5 5 10]`).
- **Usage**: Use `histogram_quantile(0.95, ...)` to calculate 95th percentile latency.

#### `http_requests_in_progress_total`
- **Type**: Gauge
- **Description**: The number of inflight requests currently being processed.

### Runtime Metrics
Standard Go runtime metrics are also exposed, including:
- `go_goroutines`: Number of goroutines that currently exist.
- `go_memstats_*`: Memory usage statistics.
- `process_cpu_seconds_total`: Total user and system CPU time spent in seconds.


## The authentication flow

The overall flow is the following. There are several actors:

- The application, acting as an OpenID Relying Party (RP). When the application wants to authenticate a user, it uses the OIDC Authentication Code Flow to pass control to the CertAuth server, which acts as an OpenID Provider (OP). The OP runs in a domain of its own (e.g. certauth.mycredential.eu).
- The OpenID Provider (OP) authenticates the user. It presents a screen describing what is going to happen, and allows the user to click a button to request the eIDAS certificate from the browser. It asks for consent to the user.
- The button redirects the user to another domain (eg. certsec.mycredential.eu). This domain is configured in the reverse proxy (we use Caddy for the examples, but any other reverse proxy would work with the proper configuration) to ask for a client certificate.

For example, in Caddy it is done with:

```
(client_auth) {
    tls {
        client_auth {
            mode require
        }
    }
}
```

- When the user's browser starts the TLS session, it presents a popup to the user to select one of the certificates in the keystore of the user machine. It even allows the user to use a smartcard or any other supported mechanism in the client machine.

- The user selects the certificate to be used (we require an eIDAS certificate, more on this later), and the browser starts the TLS session. The reverse proxy then sends the certificate to our server (at the internal port assigned to the domain certsec.mycredential.eu). In Caddy, this is done with:

```
certsec.mycredential.es {
    import client_auth
    reverse_proxy localhost:8090 {
        header_up tls-client-certificate {http.request.tls.client.certificate_der_base64}
    }   
}
```

- Caddy sends the certificate in an HTTP header (our default is `tls-client-certificate`).
- Our application receives the certificate, decodes it and extracts the user information from the certificate, mainly the Subject field.
- For this application, we require the certificate to be an "organizational" certificate, that is, either a certificate for seals (QSeal), or a certificate of representation (a QSign where the user is associated to the organization that represents). In both certificates, the Subject field contains the `organizationIdentifier` (OID 2.5.4.97). For details, see the `x509util` package in this project.
- Once this is done, the certsec.mycredential.eu server sends back to the certauth.mycredential.eu server the information about the user (essentially the fields in the Subject field of the certificate).
- The certauth server then responds back to the RP using the standard OIDC mechanism (specifically Authentication Code Flow). The user information is in the ID Token, as usual, using the standard claims when appropriate, but with claims defined to suit our needs if there are no standard claims.
- The RP then uses that information to welcome the user or whatever the application requires. The RP can also request an access token from the OP. In our simple OP, we will not support token refresh.



NOTE:
This server is based on code from [ORY Fosite example](https://github.com/ory/fosite-example) for the OpenID Provider functionality. The code maintains the copyright and attributions, but it removes unneccesary code to help keep this server simple and understandable.

