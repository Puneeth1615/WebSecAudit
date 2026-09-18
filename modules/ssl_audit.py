"""SSL/TLS Transport Security Audit Module.
Emulates Qualys SSL Labs certificate & transport posture checks.
"""

import socket
import ssl
import datetime
from typing import List, Dict, Any, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

from core.models import Finding, Severity, Category


def audit_ssl(hostname: str, port: int = 443, timeout: int = 5) -> Tuple[List[Finding], Dict[str, Any]]:
    """Perform deep transport layer and SSL/TLS certificate audit."""
    findings: List[Finding] = []
    metadata: Dict[str, Any] = {
        "ssl_enabled": False,
        "tls_version": None,
        "cipher_suite": None,
        "cert_issuer": None,
        "cert_subject": None,
        "cert_valid_from": None,
        "cert_expiry": None,
        "days_until_expiry": None,
        "key_type": None,
        "key_size": None,
        "signature_algo": None,
        "san_list": [],
    }

    ctx = ssl.create_default_context()
    # Allow inspection even if certificate is untrusted/expired so we can report on it
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw_socket = None
    ssl_socket = None

    try:
        raw_socket = socket.create_connection((hostname, port), timeout=timeout)
        ssl_socket = ctx.wrap_socket(raw_socket, server_hostname=hostname)
        metadata["ssl_enabled"] = True

        # Negotiated TLS Protocol & Cipher
        tls_version = ssl_socket.version()
        cipher_info = ssl_socket.cipher()  # (cipher_name, protocol_version, bits)
        metadata["tls_version"] = tls_version
        metadata["cipher_suite"] = cipher_info[0] if cipher_info else "Unknown"

        # Protocol Evaluation
        if tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
            findings.append(
                Finding(
                    id="TLS-LEGACY-PROTO",
                    title=f"Deprecated Transport Protocol Negotiated ({tls_version})",
                    category=Category.TRANSPORT_SECURITY,
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    description=f"The server negotiated {tls_version}. Legacy protocols are vulnerable to POODLE, BEAST, and lack modern forward secrecy.",
                    impact="Adversaries positioned on the network can decrypt or alter sensitive traffic.",
                    remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on your web server. Enforce TLS 1.2 and TLS 1.3 exclusively.",
                    evidence=f"Negotiated protocol: {tls_version}",
                    compliance_tags=["PCI-DSS 4.0: Req 4.1", "NIST SP 800-52r2", "HIPAA § 164.312(e)(1)"],
                )
            )
        elif tls_version == "TLSv1.2":
            # Informational note: TLS 1.2 is compliant, but 1.3 is recommended
            findings.append(
                Finding(
                    id="TLS-UPGRADE-1.3",
                    title="TLS 1.2 Negotiated (TLS 1.3 Recommended)",
                    category=Category.TRANSPORT_SECURITY,
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    description="The server negotiated TLS 1.2. While secure and compliant, TLS 1.3 provides enhanced handshake performance and removes legacy ciphers.",
                    impact="None. Baseline compliance is satisfied.",
                    remediation="Enable TLS 1.3 support on the web server or load balancer.",
                    evidence=f"Protocol: {tls_version}, Cipher: {metadata['cipher_suite']}",
                    compliance_tags=["Best Practice"],
                )
            )

        # Cipher Suite strength
        if cipher_info and cipher_info[2] and cipher_info[2] < 128:
            findings.append(
                Finding(
                    id="TLS-WEAK-CIPHER",
                    title=f"Weak Encryption Cipher Length ({cipher_info[2]} bits)",
                    category=Category.TRANSPORT_SECURITY,
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    description=f"The negotiated cipher suite utilizes {cipher_info[2]}-bit encryption keys, which is below the 128-bit industry standard.",
                    impact="Vulnerable to cryptanalytic attacks and data eavesdropping.",
                    remediation="Reconfigure the server cipher list to mandate 128-bit or 256-bit AES/ChaCha20 ciphers.",
                    evidence=f"Cipher: {cipher_info[0]} ({cipher_info[2]} bits)",
                    compliance_tags=["PCI-DSS 4.0: Req 4.1", "OWASP A02:2021"],
                )
            )

        # Parse DER Certificate using cryptography library
        der_cert = ssl_socket.getpeercert(binary_form=True)
        if der_cert:
            cert = x509.load_der_x509_certificate(der_cert)

            # Subject and Issuer
            subject_str = cert.subject.rfc4514_string()
            issuer_str = cert.issuer.rfc4514_string()
            metadata["cert_subject"] = subject_str
            metadata["cert_issuer"] = issuer_str

            # Validity Period (Issued and Expiration)
            not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
            if not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=datetime.timezone.utc)
            metadata["cert_valid_from"] = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")

            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=datetime.timezone.utc)
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            days_left = (not_after - now_utc).days
            metadata["cert_expiry"] = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
            metadata["days_until_expiry"] = days_left

            if days_left < 0:
                findings.append(
                    Finding(
                        id="TLS-CERT-EXPIRED",
                        title=f"SSL/TLS Certificate Has Expired ({abs(days_left)} days ago)",
                        category=Category.TRANSPORT_SECURITY,
                        severity=Severity.CRITICAL,
                        cvss_score=9.1,
                        description=f"The certificate expired on {metadata['cert_expiry']}. Browsers will trigger hard security warnings and block connections.",
                        impact="Severe disruption of trust, browser blocking, and susceptibility to man-in-the-middle attacks.",
                        remediation="Renew and deploy an active TLS certificate immediately.",
                        evidence=f"Expired on: {metadata['cert_expiry']} ({days_left} days remaining)",
                        compliance_tags=["PCI-DSS 4.0: Req 4.1", "HIPAA § 164.312(e)(1)"],
                    )
                )
            elif days_left < 30:
                findings.append(
                    Finding(
                        id="TLS-CERT-EXPIRING-SOON",
                        title=f"SSL/TLS Certificate Expiring Soon ({days_left} days remaining)",
                        category=Category.TRANSPORT_SECURITY,
                        severity=Severity.HIGH,
                        cvss_score=7.0,
                        description=f"The certificate will expire in {days_left} days on {metadata['cert_expiry']}.",
                        impact="If not renewed promptly, traffic will be blocked by modern user agents.",
                        remediation="Automate certificate renewal via ACME / Let's Encrypt or deploy new CA cert.",
                        evidence=f"Expires: {metadata['cert_expiry']}",
                        compliance_tags=["Operational Hygiene"],
                    )
                )

            # Self-signed check
            if subject_str == issuer_str:
                findings.append(
                    Finding(
                        id="TLS-CERT-SELFSIGNED",
                        title="Self-Signed SSL/TLS Certificate Detected",
                        category=Category.TRANSPORT_SECURITY,
                        severity=Severity.HIGH,
                        cvss_score=7.4,
                        description="The certificate issuer matches the subject, indicating it is self-signed and not signed by a trusted Certificate Authority (CA).",
                        impact="Clients cannot verify the authenticity of the server, opening users to MITM attacks.",
                        remediation="Replace the self-signed certificate with a certificate from a trusted public or internal enterprise CA.",
                        evidence=f"Subject: {subject_str} == Issuer: {issuer_str}",
                        compliance_tags=["PCI-DSS 4.0: Req 4.1", "OWASP A02:2021"],
                    )
                )

            # Public Key Size and Algorithm
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                metadata["key_type"] = "RSA"
                metadata["key_size"] = pub_key.key_size
                if pub_key.key_size < 2048:
                    findings.append(
                        Finding(
                            id="TLS-WEAK-RSA-KEY",
                            title=f"Weak RSA Key Size ({pub_key.key_size} bits)",
                            category=Category.TRANSPORT_SECURITY,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=f"RSA public key length is {pub_key.key_size} bits. NIST deprecates keys shorter than 2048 bits due to factoring risk.",
                            impact="Potential cryptographic compromise of session confidentiality.",
                            remediation="Generate new private keys with at least 2048-bit RSA (or 256-bit ECDSA).",
                            evidence=f"RSA Key Length: {pub_key.key_size} bits",
                            compliance_tags=["NIST SP 800-57", "PCI-DSS 4.0: Req 4.1"],
                        )
                    )
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                metadata["key_type"] = "ECDSA"
                metadata["key_size"] = pub_key.curve.key_size
            elif isinstance(pub_key, dsa.DSAPublicKey):
                metadata["key_type"] = "DSA"
                metadata["key_size"] = pub_key.key_size

            # Signature Algorithm
            sig_algo = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else "unknown"
            metadata["signature_algo"] = sig_algo
            if sig_algo in ["md5", "sha1"]:
                findings.append(
                    Finding(
                        id="TLS-WEAK-SIG-ALGO",
                        title=f"Insecure Certificate Signature Algorithm ({sig_algo.upper()})",
                        category=Category.TRANSPORT_SECURITY,
                        severity=Severity.HIGH,
                        cvss_score=7.4,
                        description=f"The certificate uses the {sig_algo.upper()} hashing algorithm, which has known collision vulnerabilities.",
                        impact="Attackers can forge fraudulent certificates leading to traffic interception.",
                        remediation="Reissue certificate using SHA-256 or stronger signature digest.",
                        evidence=f"Signature algorithm: {sig_algo}",
                        compliance_tags=["OWASP A02:2021", "PCI-DSS 4.0: Req 4.1"],
                    )
                )

            # Subject Alternative Names (SAN) Validation
            san_names = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_names = san_ext.value.get_values_for_type(x509.DNSName)
                metadata["san_list"] = san_names
            except x509.ExtensionNotFound:
                pass

            # Match hostname against SANs
            if san_names:
                matches = False
                clean_host = hostname.lower()
                for san in san_names:
                    san_clean = san.lower()
                    if san_clean == clean_host:
                        matches = True
                        break
                    if san_clean.startswith("*."):
                        wildcard_domain = san_clean[2:]
                        if clean_host.endswith(wildcard_domain) and clean_host.count(".") == wildcard_domain.count(".") + 1:
                            matches = True
                            break
                if not matches:
                    findings.append(
                        Finding(
                            id="TLS-SAN-MISMATCH",
                            title=f"Certificate Name Mismatch for Hostname '{hostname}'",
                            category=Category.TRANSPORT_SECURITY,
                            severity=Severity.HIGH,
                            cvss_score=7.4,
                            description=f"The hostname '{hostname}' does not match any DNS names listed in the certificate Subject Alternative Names (SAN).",
                            impact="Browsers will warn users that the site is untrusted or impersonated.",
                            remediation="Ensure the certificate's SAN list includes all intended domain names and subdomains.",
                            evidence=f"Target: {hostname} | SANs: {', '.join(san_names[:5])}",
                            compliance_tags=["RFC 6125", "PCI-DSS 4.0: Req 4.1"],
                        )
                    )

    except (socket.timeout, ConnectionRefusedError, OSError) as net_err:
        findings.append(
            Finding(
                id="TLS-CONN-FAILED",
                title=f"TLS/HTTPS Handshake Failed on Port {port}",
                category=Category.TRANSPORT_SECURITY,
                severity=Severity.HIGH,
                cvss_score=7.5,
                description=f"Unable to establish TLS connection with {hostname}:{port}. {str(net_err)}",
                impact="Transport security cannot be verified or HTTPS is not properly configured.",
                remediation="Ensure port 443 is open, accepting connections, and configured with a valid SSL/TLS service.",
                evidence=str(net_err),
                compliance_tags=["OWASP A02:2021", "PCI-DSS 4.0"],
            )
        )
    except Exception as e:
        findings.append(
            Finding(
                id="TLS-INSPECTION-ERR",
                title="TLS Certificate Inspection Error",
                category=Category.TRANSPORT_SECURITY,
                severity=Severity.MEDIUM,
                cvss_score=5.0,
                description=f"Error encountered while parsing TLS certificate: {str(e)}",
                impact="Transport layer verification incomplete.",
                remediation="Check web server TLS handshake configuration.",
                evidence=str(e),
                compliance_tags=["Operational Hygiene"],
            )
        )
    finally:
        if ssl_socket:
            try:
                ssl_socket.close()
            except Exception:
                pass
        if raw_socket:
            try:
                raw_socket.close()
            except Exception:
                pass

    return findings, metadata
