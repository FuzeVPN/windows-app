# SPDX-License-Identifier: MPL-2.0
"""Regenerate public, synthetic TLS fixtures without retaining private keys.

Requires Python's cryptography package. These certificates are exclusively for
the isolated in-memory CryptoAPI tests; never install them in a Windows store.
"""

from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def subject(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def certificate(name, public_key, issuer, issuer_key, *, ca=False, path_length=None,
                expired=False, client_only=False, dns_name="api.fuzevpn.com"):
    start = datetime(2010 if expired else 2020, 1, 1, tzinfo=timezone.utc)
    end = datetime(2019 if expired else 2049, 1, 1, tzinfo=timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length),
                       critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True,
                                    content_commitment=False,
                                    key_encipherment=not ca,
                                    data_encipherment=False,
                                    key_agreement=False,
                                    key_cert_sign=ca,
                                    crl_sign=ca,
                                    encipher_only=None,
                                    decipher_only=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False,
        ).add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client_only
            else ExtendedKeyUsageOID.SERVER_AUTH
        ]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def main():
    output = Path(__file__).resolve().parent
    root_key, intermediate_key, leaf_key, standalone_key = (
        key(), key(), key(), key()
    )
    root_name = subject("FuzeVPN synthetic TLS test root - never install")
    intermediate_name = subject("FuzeVPN synthetic TLS test intermediate")
    leaf_name = subject("api.fuzevpn.com")
    fixtures = {
        "root.pem": certificate(root_name, root_key.public_key(), root_name,
                                root_key, ca=True, path_length=1),
        "intermediate.pem": certificate(
            intermediate_name, intermediate_key.public_key(), root_name,
            root_key, ca=True, path_length=0),
        "expired-intermediate.pem": certificate(
            intermediate_name, intermediate_key.public_key(), root_name,
            root_key, ca=True, path_length=0, expired=True),
        "valid.pem": certificate(leaf_name, leaf_key.public_key(),
                                 intermediate_name, intermediate_key),
        "expired.pem": certificate(leaf_name, leaf_key.public_key(),
                                   intermediate_name, intermediate_key,
                                   expired=True),
        "client-only.pem": certificate(leaf_name, leaf_key.public_key(),
                                       intermediate_name, intermediate_key,
                                       client_only=True),
        "wrong-host.pem": certificate(subject("other.fuzevpn.test"),
                                      leaf_key.public_key(), intermediate_name,
                                      intermediate_key,
                                      dns_name="other.fuzevpn.test"),
        "self-signed-leaf.pem": certificate(
            leaf_name, standalone_key.public_key(), leaf_name, standalone_key),
    }
    for filename, cert in fixtures.items():
        (output / filename).write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )


if __name__ == "__main__":
    main()
