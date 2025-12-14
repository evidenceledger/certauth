# OpenID Provider for authenticating users with an eIDAS digital certificate

This project implements two different but related functionalities:

1. A minimalist OpenID Provider (OP) focused on only one thing: enable applications to authenticate users using their eIDAS certificate issued to them by a QTSP (Qualified Trust Service Provider). This project does not have to provide all the features that "normal" OPs provide.

2. A registration service that applications can use to onboard users with their eIDAS certificate. This service relies on the previous one to authenticate users with their eIDAS certificate.

The eIDAS certificate of the users is validated against the EU Trusted Lists (https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls), ensuring the association of the certificate with the real-world identity of the user, either as a natural person or as a natural person who is a legal representative of an organization. In both cases, the identity of the user has been validated by one of the more than 200 QTSPs in the EU, which are highly regulated entities. In the case of a legal representative, the identity of the organization has been validated by the issuer QTSP, together with the relationship of the user with the organization.

## Deployment

The deployment of this project is very simple using Docker. With other infrastructure, it should be very simple to map into its requirements.

The project includes a Dockerfile which can be used to generate a Docker image. When creating a container instance, the folowing environment variables have to be provided.

For the endpoints composing the onboarding system: 

- `CERTAUTH_DEVELOPMENT`: Optional. Set to `true` to enable development mode. This will disable some security features and enable some development features. if you omit it or set it to `false`, the server will be in production mode.
- `CERTAUTH_URL`: The URL for the CertAuth server.
- `CERTAUTH_PORT`: Optional. The port for the CertAuth server. If you omit it the default is `8010`.
- `CERTSEC_URL`: The URL for the CertSec server.
- `CERTSEC_PORT`: Optional. The port for the CertSec server. If you omit it the default is `8011`.
- `ONBOARD_URL`: The URL for the Onboard server.
- `ONBOARD_PORT`: Optional. The port for the Onboard server. If you omit it the default is `8012`.

For sending emails to the users:

- `SMTP_HOST`: The host for the SMTP server.
- `SMTP_PORT`: The port for the SMTP server.
- `SMTP_USERNAME`: The username for the SMTP server.
- `SMTP_PASSWORD`: The password for the SMTP server.
- `FROM_EMAIL`: The email address to use as the sender.
- `FROM_NAME`: The name to use as the sender.

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

