"""
X.509 certificate parsing and CA resolution.
"""

from typing import Dict, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


def parse_certificate(cert_bytes: bytes) -> Optional[x509.Certificate]:
    """
    Parse a DER-encoded X.509 certificate.

    Args:
        cert_bytes: DER-encoded certificate bytes

    Returns:
        Parsed certificate or None if parsing fails
    """
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        return cert
    except Exception as e:
        print(f"Error parsing certificate: {e}")
        return None


def extract_dn_info(name: x509.Name) -> Dict[str, str]:
    """
    Extract Distinguished Name components into a dict.

    Args:
        name: X.509 Name object

    Returns:
        Dict with cn, o, ou, c fields
    """
    info = {}

    try:
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            info["cn"] = cn[0].value
    except Exception:
        pass

    try:
        o = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if o:
            info["o"] = o[0].value
    except Exception:
        pass

    try:
        ou = name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        if ou:
            info["ou"] = ou[0].value
    except Exception:
        pass

    try:
        c = name.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        if c:
            info["c"] = c[0].value
    except Exception:
        pass

    return info


def is_self_signed(cert: x509.Certificate) -> bool:
    """
    Check if a certificate is self-signed (root CA).

    Args:
        cert: X.509 certificate

    Returns:
        True if self-signed, False otherwise
    """
    # Check if issuer == subject
    return cert.issuer == cert.subject


def get_ca_info(cert: x509.Certificate) -> Dict[str, any]:
    """
    Extract CA information from a certificate.

    Args:
        cert: X.509 certificate

    Returns:
        Dict with issuer and subject information
    """
    issuer_info = extract_dn_info(cert.issuer)
    subject_info = extract_dn_info(cert.subject)

    return {
        "issuer": issuer_info,
        "subject": subject_info,
        "is_self_signed": is_self_signed(cert),
        "not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before),
        "not_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)
    }


def normalize_ca_name(issuer_info: Dict[str, str]) -> str:
    """
    Normalize CA name for consistent reporting.

    Args:
        issuer_info: Dict with cn, o, ou, c fields

    Returns:
        Normalized CA name string
    """
    # Prefer organization name, fall back to CN
    if "o" in issuer_info and issuer_info["o"]:
        ca_name = issuer_info["o"]
    elif "cn" in issuer_info and issuer_info["cn"]:
        ca_name = issuer_info["cn"]
    else:
        ca_name = "Unknown"

    # Add country if available for disambiguation
    if "c" in issuer_info and issuer_info["c"]:
        ca_name = f"{ca_name} ({issuer_info['c']})"

    return ca_name


def get_root_ca(cert: x509.Certificate) -> str:
    """
    Get the root CA name from a certificate.
    For now, we'll use the immediate issuer since we're not walking the chain yet.

    Args:
        cert: X.509 certificate

    Returns:
        Root CA name
    """
    ca_info = get_ca_info(cert)

    # If self-signed, this is the root
    if ca_info["is_self_signed"]:
        return normalize_ca_name(ca_info["subject"])

    # Otherwise, use the issuer (we'll enhance this to walk the chain in a future iteration)
    return normalize_ca_name(ca_info["issuer"])
