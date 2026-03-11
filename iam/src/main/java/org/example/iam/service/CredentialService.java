// File: src/main/java/org/example/iam/service/CredentialService.java
package org.example.iam.service;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Interface for loading cryptographic credentials.
 */
public interface CredentialService {

    /**
     * Loads a PrivateKey from a specified location/reference.
     * Handles necessary decryption of passwords if stored encrypted.
     *
     * @param credentialRef      Reference to the credential storage (e.g., keystore file path).
     * @param keyAlias           The alias identifying the key within the store.
     * @param keystorePasswordRef Reference to the (potentially encrypted) password for the keystore file.
     * @param keyPasswordRef     Reference to the (potentially encrypted) password for the private key entry itself (can be null if same as keystore password).
     * @return The loaded PrivateKey.
     * @throws RuntimeException if the key cannot be loaded or decrypted.
     */
    PrivateKey loadPrivateKey(String credentialRef, String keyAlias, String keystorePasswordRef, String keyPasswordRef); // Signature updated

    /**
     * Loads an X.509 Certificate from a specified location/reference (e.g., keystore file path).
     *
     * @param credentialRef      Reference to the credential storage (e.g., file path to PKCS#12).
     * @param keyAlias           The alias identifying the certificate within the store (if applicable).
     * @param keystorePasswordRef Reference to the (potentially encrypted) password for the keystore (if applicable).
     * @return The loaded X509Certificate.
     * @throws RuntimeException if the certificate cannot be loaded or parsed.
     */
    X509Certificate loadCertificate(String credentialRef, String keyAlias, String keystorePasswordRef);

    /**
     * Loads an X.509 Certificate directly from a PEM-encoded string.
     *
     * @param pemData The certificate data in PEM format.
     * @return The loaded X509Certificate.
     * @throws RuntimeException if the certificate cannot be parsed.
     */
    X509Certificate loadCertificateFromPem(String pemData);

}