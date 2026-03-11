// File: src/main/java/org/example/iam/security/JwtUtils.java
package org.example.iam.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException; // Specific exception
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.entity.User; // For generating token from User entity
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Utility class for handling JSON Web Token (JWT) operations: generation, validation, and claim extraction.
 * Uses the modern `io.jsonwebtoken` (jjwt) library API.
 * <p>
 * Reads the JWT secret and expiration time from application properties.
 * Provides methods to create tokens from authenticated User details and validate incoming tokens.
 * </p>
 */
@Component
@Slf4j
public class JwtUtils {

  // --- Constants for Custom Claims ---
  private static final String CLAIM_ROLES = "roles";
  private static final String CLAIM_ORG_ID = "org_id";
  private static final String CLAIM_ORG_DOMAIN = "org_domain"; // Potentially useful claim
  private static final String CLAIM_USER_ID = "user_id";

  // --- Configuration from application.properties ---
  @Value("${security.jwt.secret}")
  private String jwtSecret;

  @Value("${security.jwt.expiration-ms}")
  private long jwtExpirationMs;

  /**
   * The secret key used for signing and verifying JWTs (HMAC-SHA).
   * Initialized from the base64 encoded secret in properties during post-construction.
   */
  private SecretKey signingKey;

  /**
   * Initializes the signing key after the bean is constructed.
   * Decodes the Base64 secret from properties and creates a SecretKey instance.
   * Logs an error and throws an exception if the secret key configuration is invalid.
   */
  @PostConstruct
  private void init() {
    log.debug("Initializing JWT signing key...");
    try {
      byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
      if (keyBytes.length < 32) { // HS256 requires at least 256 bits (32 bytes)
        log.error("!!! JWT secret key is too short (must be at least 256 bits / 32 bytes after Base64 decoding) !!!");
        throw new IllegalArgumentException("JWT secret key is too short.");
      }
      this.signingKey = Keys.hmacShaKeyFor(keyBytes);
      log.info("JWT signing key initialized successfully.");
    } catch (IllegalArgumentException e) {
      log.error("!!! Invalid Base64 encoding or length for JWT secret key in properties !!!", e);
      // Halt application startup if key is invalid
      throw new IllegalStateException("Invalid JWT secret key configuration", e);
    }
  }

  /**
   * Safely retrieves the signing key, initializing it if necessary.
   * @return The SecretKey instance.
   * @throws IllegalStateException if the key could not be initialized.
   */
  private SecretKey getSignKey() {
    // Double-check initialization, although @PostConstruct should handle it.
    if (this.signingKey == null) {
      log.warn("JWT signing key was null, attempting re-initialization.");
      init(); // Attempt to initialize again
      if (this.signingKey == null) {
        // If still null, something is seriously wrong with configuration loading.
        throw new IllegalStateException("JWT signing key could not be initialized.");
      }
    }
    return signingKey;
  }

  // --- Token Generation ---

  /**
   * Generates a JWT for the given Spring Security Authentication object.
   * Expects the principal within the Authentication object to be a {@link User} entity instance.
   *
   * @param authentication The authenticated Authentication object.
   * @return A JWT string.
   * @throws IllegalArgumentException if the principal is not a User instance.
   */
  public String generateToken(Authentication authentication) {
    Object principal = authentication.getPrincipal();
    // Ensure the principal is our User entity which contains necessary details (ID, Org)
    if (!(principal instanceof User userDetails)) {
      log.error("Cannot generate JWT: Principal is not an instance of User. Principal type: {}",
              principal.getClass().getName());
      throw new IllegalArgumentException("Cannot generate JWT from principal type: " + principal.getClass().getName());
    }
    return generateToken(userDetails);
  }

  /**
   * Generates a JWT for the given User entity.
   * Includes standard claims (subject, issuedAt, expiration) and custom claims
   * (roles, user ID, organization ID, organization domain).
   *
   * @param userDetails The User entity containing user details.
   * @return A JWT string.
   */
  public String generateToken(User userDetails) {
    if (userDetails == null || userDetails.getUsername() == null) {
      throw new IllegalArgumentException("Cannot generate JWT for null user or user with null username.");
    }

    Map<String, Object> claims = new HashMap<>();
    // Add custom claims
    claims.put(CLAIM_ROLES, userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
    claims.put(CLAIM_USER_ID, userDetails.getId().toString());
    if (userDetails.getOrganization() != null) {
      claims.put(CLAIM_ORG_ID, userDetails.getOrganization().getId().toString());
      claims.put(CLAIM_ORG_DOMAIN, userDetails.getOrganization().getOrgDomain());
    } else {
      log.warn("Generating JWT for user '{}' (ID: {}) with no associated Organization!",
              userDetails.getUsername(), userDetails.getId());
    }

    // Create the token using the private helper method
    return createToken(claims, userDetails.getUsername());
  }

  /**
   * Private helper method to construct the JWT string using the modern jjwt API builder.
   *
   * @param claims  A map of custom claims to include in the token payload.
   * @param subject The subject of the token (typically the username).
   * @return The compacted JWT string.
   */
  private String createToken(Map<String, Object> claims, String subject) {
    Instant now = Instant.now();
    Instant expiryDate = now.plusMillis(jwtExpirationMs);

    log.debug("Creating JWT for subject: '{}', IssuedAt: {}, ExpiresAt: {}", subject, now, expiryDate);

    // Use the modern builder approach with the initialized SecretKey
    return Jwts.builder()
            .claims(claims)                 // Set all custom claims
            .subject(subject)               // Set the standard 'sub' claim (username)
            .issuedAt(Date.from(now))       // Set the standard 'iat' claim
            .expiration(Date.from(expiryDate)) // Set the standard 'exp' claim
            .signWith(getSignKey())         // Sign using the pre-initialized HMAC-SHA key
            .compact();                     // Build and serialize the token
  }

  // --- Claim Extraction ---

  /**
   * Extracts the username (subject) from the JWT token.
   *
   * @param token The JWT string.
   * @return The username string.
   * @throws JwtException if the token cannot be parsed or verified.
   */
  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  /**
   * Extracts the expiration date from the JWT token.
   *
   * @param token The JWT string.
   * @return The expiration date.
   * @throws JwtException if the token cannot be parsed or verified.
   */
  public Date extractExpirationDate(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  /**
   * Extracts the user ID (UUID) from the custom claims of the JWT token.
   *
   * @param token The JWT string.
   * @return The user's UUID, or null if the claim is missing.
   * @throws JwtException           if the token cannot be parsed or verified.
   * @throws IllegalArgumentException if the claim value is not a valid UUID string.
   */
  public UUID extractUserId(String token) {
    String userIdStr = extractClaim(token, claims -> claims.get(CLAIM_USER_ID, String.class));
    try {
      return userIdStr != null ? UUID.fromString(userIdStr) : null;
    } catch (IllegalArgumentException e) {
      log.error("Invalid UUID format for user ID claim in token: '{}'", userIdStr, e);
      throw new MalformedJwtException("Invalid user ID claim format in token", e);
    }
  }

  /**
   * Extracts the organization ID (UUID) from the custom claims of the JWT token.
   *
   * @param token The JWT string.
   * @return The organization's UUID, or null if the claim is missing.
   * @throws JwtException           if the token cannot be parsed or verified.
   * @throws IllegalArgumentException if the claim value is not a valid UUID string.
   */
  public UUID extractOrganizationId(String token) {
    String orgIdStr = extractClaim(token, claims -> claims.get(CLAIM_ORG_ID, String.class));
    try {
      return orgIdStr != null ? UUID.fromString(orgIdStr) : null;
    } catch (IllegalArgumentException e) {
      log.error("Invalid UUID format for organization ID claim in token: '{}'", orgIdStr, e);
      throw new MalformedJwtException("Invalid organization ID claim format in token", e);
    }
  }

  /**
   * Extracts the list of roles (as strings) from the custom claims of the JWT token.
   *
   * @param token The JWT string.
   * @return A list of role strings, or null/empty list if the claim is missing or not a list.
   * @throws JwtException if the token cannot be parsed or verified.
   */
  @SuppressWarnings("unchecked") // Necessary cast for generic List claim
  public List<String> extractRoles(String token) {
    // Be cautious with direct casting; ensure the claim is indeed stored as List<String>.
    return extractClaim(token, claims -> claims.get(CLAIM_ROLES, List.class));
  }

  /**
   * Generic method to extract a specific claim from the token using a claims resolver function.
   *
   * @param token          The JWT string.
   * @param claimsResolver A function that takes Claims and returns the desired claim value.
   * @param <T>            The type of the claim value.
   * @return The extracted claim value.
   * @throws JwtException if the token cannot be parsed or verified.
   */
  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  /**
   * Parses the JWT token using the configured signing key and returns all claims.
   * Handles various JWT exceptions and logs them appropriately.
   *
   * @param token The JWT string.
   * @return The Claims object containing all claims from the token payload.
   * @throws JwtException subclasses (ExpiredJwtException, MalformedJwtException, SignatureException, etc.)
   * if parsing or verification fails.
   */
  private Claims extractAllClaims(String token) {
    log.trace("Attempting to parse and verify JWT token.");
    try {
      // Use the modern parser builder with the signing key
      return Jwts.parser()
              .verifyWith(getSignKey()) // Specify the key for verification
              .build()
              .parseSignedClaims(token) // Use parseSignedClaims for JWS (signed JWTs)
              .getPayload(); // Get the claims payload
    } catch (ExpiredJwtException e) {
      log.warn("JWT parsing failed: Token expired at {}. Message: {}", e.getClaims().getExpiration(), e.getMessage());
      throw e; // Re-throw specific exception
    } catch (UnsupportedJwtException e) {
      log.warn("JWT parsing failed: Unsupported token format. Message: {}", e.getMessage());
      throw e;
    } catch (MalformedJwtException e) {
      log.warn("JWT parsing failed: Malformed token. Message: {}", e.getMessage());
      throw e;
    } catch (SignatureException e) {
      log.warn("JWT parsing failed: Invalid signature. Message: {}", e.getMessage());
      throw e;
    } catch (IllegalArgumentException e) {
      // Handles null/empty token string or other invalid arguments to parser
      log.warn("JWT parsing failed: Invalid argument. Message: {}", e.getMessage());
      throw e;
    } catch (JwtException e) { // Catch-all for other jjwt exceptions
      log.warn("JWT parsing failed: General JWT exception. Message: {}", e.getMessage());
      throw e;
    }
  }

  // --- Validation ---

  /**
   * Checks if the JWT token has expired without throwing an exception during parsing.
   *
   * @param token The JWT string.
   * @return {@code true} if the token is expired, {@code false} otherwise.
   * Also returns {@code true} if the token is invalid/unparsable.
   */
  private boolean isTokenExpired(String token) {
    try {
      // Check expiration without throwing if already expired
      return extractExpirationDate(token).before(new Date());
    } catch (ExpiredJwtException e) {
      return true; // Explicitly expired
    } catch (JwtException e) {
      log.warn("Could not determine expiration status due to invalid token: {}", e.getMessage());
      return true; // Treat unparsable/invalid tokens as effectively expired/unusable
    }
  }

  /**
   * Validates the JWT token against the provided UserDetails.
   * Checks if the username in the token matches the UserDetails username and if the token is not expired.
   *
   * @param token       The JWT string.
   * @param userDetails The UserDetails object loaded for the user identified in the token.
   * @return {@code true} if the token is valid for the given user, {@code false} otherwise.
   */
  public boolean validateToken(String token, UserDetails userDetails) {
    try {
      final String usernameFromToken = extractUsername(token);
      final boolean isUsernameMatch = usernameFromToken != null && usernameFromToken.equals(userDetails.getUsername());
      final boolean isNotExpired = !isTokenExpired(token); // Handles parsing exceptions internally

      if (!isUsernameMatch) {
        log.warn("JWT validation failed: Username mismatch (Token: '{}', UserDetails: '{}')",
                usernameFromToken, userDetails.getUsername());
      }
      if (!isNotExpired) {
        log.warn("JWT validation failed: Token expired for user '{}'", usernameFromToken);
      }

      return isUsernameMatch && isNotExpired;

    } catch (JwtException e) {
      // Catch exceptions from extractUsername if validation fails early (e.g., bad signature)
      log.warn("JWT validation failed due to parsing/verification error: {}", e.getMessage());
      return false;
    }
  }
}