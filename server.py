#!/usr/bin/env python3

import pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import logging
from rich.logging import RichHandler

logging.basicConfig(
    level=logging.DEBUG,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)


def ensure_snakeoil(key_fn: pathlib.Path, cert_fn: pathlib.Path):
    if key_fn.exists() and cert_fn.exists():
        return (key_fn, cert_fn)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SnakOil"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "SnakeOil City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SnakeOil Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(key_fn, "wb") as f:
        assert (
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            > 0
        )

    with open(cert_fn, "wb") as f:
        assert f.write(cert.public_bytes(serialization.Encoding.PEM)) > 0

    return (key_fn, cert_fn)


def main():
    (key_fn, cert_fn) = ensure_snakeoil(
        pathlib.Path("./snakeoil.key"), pathlib.Path("snakeoil.crt")
    )

    log = logging.getLogger("server")

    def fake_auth(self, cert, req):
        log.info(cert)
        log.info(req)
        credentials = []
        if req.request_header.authentication is not None:
            credentials = req.request_header.authentication.credentials
        return "anon", "anon"

    from kmip.services.server.session import KmipSession

    KmipSession.authenticate = fake_auth
    from kmip.services.server import KmipServer

    server = KmipServer(
        hostname="127.0.0.1",
        port=5696,
        certificate_path=cert_fn.as_posix(),
        ca_path=cert_fn.as_posix(),
        key_path=key_fn.as_posix(),
        auth_suite="TLS1.2",
        log_path="./server.log",
        config_path="",
        enable_tls_client_auth=False,
        logging_level="DEBUG",
        database_path="pykmip.db",
    )
    with server:
        server.serve()


main()
