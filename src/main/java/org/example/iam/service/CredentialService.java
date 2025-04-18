// File: src/main/java/org/example/iam/service/CredentialService.java
package org.example.iam.service;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Interface for a service responsible for loading cryptographic credentials,
 * such as private keys and X.509 certificates, from secure storage.
 * Used primarily for SAML SP credential loading.
 */
public interface CredentialService {

    /**
     * Loads a PrivateKey from a specified location/reference (e.g., keystore file path).
     * Handles necessary decryption of passwords if stored encrypted.
     *
     * @param credentialRef Reference to the credential storage (e.g., file path to PKCS#12).
     * @param keyAlias      The alias identifying the key within the store.
     * @param passwordRef   Reference to the (potentially encrypted) password for the keystore or key.
     * @return The loaded PrivateKey.
     * @throws RuntimeException if the key cannot be loaded or decrypted.
     */
    PrivateKey loadPrivateKey(String credentialRef, String keyAlias, String passwordRef);

    /**
     * Loads an X.509 Certificate from a specified location/reference (e.g., keystore file path or PEM string).
     *
     * @param credentialRef Reference to the credential storage (e.g., file path to PKCS#12 or PEM data).
     * @param keyAlias      The alias identifying the certificate within the store (if applicable, null otherwise).
     * @param passwordRef   Reference to the (potentially encrypted) password for the keystore (if applicable, null otherwise).
     * @return The loaded X509Certificate.
     * @throws RuntimeException if the certificate cannot be loaded or parsed.
     */
    X509Certificate loadCertificate(String credentialRef, String keyAlias, String passwordRef);

    /**
     * Loads an X.509 Certificate directly from a PEM-encoded string.
     *
     * @param pemData The certificate data in PEM format.
     * @return The loaded X509Certificate.
     * @throws RuntimeException if the certificate cannot be parsed.
     */
    X509Certificate loadCertificateFromPem(String pemData);

}