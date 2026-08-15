#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  OtaFleetServer — TLS certificate template
//  Copy this file to tls_cert.h and replace the placeholders below with your
//  own self-signed certificate. tls_cert.h is gitignored and must NOT be
//  committed to source control.
//
//  Generate a cert:
//    openssl req -x509 -newkey rsa:2048 \
//      -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=OtaFleetServer"
//
//  Fleet devices use WiFiClientSecure with setInsecure() — no CA chain needed.
// ─────────────────────────────────────────────────────────────────────────────

#define SERVER_CERT_PEM R"(
-----BEGIN CERTIFICATE-----
REPLACE_WITH_YOUR_OWN_CERTIFICATE
-----END CERTIFICATE-----
)"

#define SERVER_KEY_PEM R"(
-----BEGIN PRIVATE KEY-----
REPLACE_WITH_YOUR_OWN_PRIVATE_KEY
-----END PRIVATE KEY-----
)"
