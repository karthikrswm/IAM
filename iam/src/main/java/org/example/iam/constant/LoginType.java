// File: src/main/java/org/example/iam/constant/LoginType.java
package org.example.iam.constant;

/**
 * Defines the allowed login mechanisms that can be configured for an Organization's regular users.
 * This determines how non-Super users belonging to an organization authenticate.
 */
public enum LoginType {
  /**
   * Standard username/password authentication managed internally by this IAM service.
   * Issues JSON Web Tokens (JWT) upon successful authentication.
   */
  JWT,

  /**
   * Single Sign-On (SSO) using the Security Assertion Markup Language (SAML) 2.0 protocol.
   * Authentication is delegated to an external Identity Provider (IdP).
   * Requires SAML configuration ({@link org.example.iam.entity.SamlConfig}) for the organization.
   */
  SAML,

  /**
   * Authentication using the OAuth 2.0 / OpenID Connect (OIDC) protocol.
   * Authentication is delegated to an external Authorization Server / OIDC Provider.
   * Requires OAuth2 client configuration ({@link org.example.iam.entity.Oauth2Config}) for the organization.
   */
  OAUTH2
}