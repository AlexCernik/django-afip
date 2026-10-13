from __future__ import annotations

from typing import IO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7Options, PKCS7SignatureBuilder
from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute, load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from django_afip import exceptions


def create_embeded_pkcs7_signature(data: bytes, cert: bytes, key: bytes) -> bytes:
    """Creates an embedded ("nodetached") PKCS7 signature.

    This is equivalent to the output of::

        openssl smime -sign -signer cert -inkey key -outform DER -nodetach < data
    """

    try:
        pkey = load_pem_private_key(key, None)
        signcert = load_pem_x509_certificate(cert)
    except Exception as e:
        raise exceptions.CorruptCertificate from e

    if not isinstance(pkey, RSAPrivateKey):
        raise exceptions.CorruptCertificate("Private key is not RSA")

    return (
        PKCS7SignatureBuilder()
        .set_data(data)
        .add_signer(signcert, pkey, hashes.SHA256())
        .sign(Encoding.DER, [PKCS7Options.Binary])
    )


def create_key(file_: IO[bytes]) -> None:
    """Create a key and write it into ``file_``."""
    # Genera la clave RSA privada usando cryptography
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Exporta la clave a formato PEM sin contraseña
    pem_key = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    file_.write(pem_key)
    file_.flush()


def create_csr(
    key_file: IO[bytes],
    organization_name: str,
    common_name: str,
    serial_number: str,
    file_: IO[bytes],
) -> None:
    """Create a certificate signing request and write it into ``file_``."""
    # Carga la clave privada
    private_key = load_pem_private_key(key_file.read(), password=None)

    # Construye los atributos del sujeto (Subject) para la AFIP
    subject = Name([
        NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        NameAttribute(NameOID.COMMON_NAME, common_name),
        NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
    ])

    # Crea y firma el CSR usando SHA256 (necesario para AFIP)
    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    # Guarda el CSR en formato PEM
    file_.write(csr.public_bytes(Encoding.PEM))
    file_.flush()
