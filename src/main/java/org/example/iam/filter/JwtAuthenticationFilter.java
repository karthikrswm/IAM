// File: src/main/java/org/example/iam/filter/JwtAuthenticationFilter.java
package org.example.iam.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException; // Catch broader JWT exceptions
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.exception.InvalidTokenException;
import org.example.iam.exception.TokenExpiredException;
import org.example.iam.security.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.NonNull; // Use Spring's NonNull for clarity
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver; // Import for exception delegation

import java.io.IOException;

/**
 * A Spring Security filter that intercepts incoming HTTP requests once per request
 * to process JWT-based authentication.
 * <p>
 * It performs the following steps:
 * <ol>
 * <li>Extracts the JWT from the {@code Authorization: Bearer <token>} header.</li>
 * <li>Validates the token's signature, expiration, and structure using {@link JwtUtils}.</li>
 * <li>If the token is valid, extracts the username.</li>
 * <li>Loads the corresponding {@link UserDetails} using the configured {@link UserDetailsService}.</li>
 * <li>Validates the token against the loaded UserDetails.</li>
 * <li>If valid, creates an {@link UsernamePasswordAuthenticationToken} and sets it in the
 * {@link SecurityContextHolder}, effectively authenticating the user for the current request.</li>
 * <li>Delegates any exceptions encountered during processing (e.g., expired token, invalid signature)
 * to the {@link HandlerExceptionResolver} to ensure consistent error handling via
 * {@link org.example.iam.exception.GlobalExceptionHandler}.</li>
 * </ol>
 * The filter then continues the filter chain, allowing subsequent security checks (like authorization)
 * to proceed based on the established authentication context.
 * </p>
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";

  private final JwtUtils jwtUtils;
  private final UserDetailsService userDetailsService;

  // Inject using @Autowired and @Qualifier on the field
  @Autowired
  @Qualifier("handlerExceptionResolver")
  private HandlerExceptionResolver exceptionResolver;

  // Explicit Constructor for final fields needed by @Autowired target
  public JwtAuthenticationFilter(JwtUtils jwtUtils, @Qualifier("userDetailsService") UserDetailsService userDetailsService) {
    this.jwtUtils = jwtUtils;
    this.userDetailsService = userDetailsService;
  }

  /**
   * Processes the incoming request to perform JWT authentication.
   *
   * @param request     The incoming HttpServletRequest.
   * @param response    The outgoing HttpServletResponse.
   * @param filterChain The filter chain to pass the request along.
   * @throws ServletException If an internal servlet error occurs.
   * @throws IOException      If an I/O error occurs.
   */
  @Override
  protected void doFilterInternal(
          @NonNull HttpServletRequest request, // Mark parameters as NonNull
          @NonNull HttpServletResponse response,
          @NonNull FilterChain filterChain)
          throws ServletException, IOException {

    final String requestUri = request.getRequestURI(); // Get URI early for logging context

    try {
      // 1. Extract Authorization Header
      final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
      final String jwt;
      final String username;

      // 2. Check Header Presence and Format
      if (!StringUtils.hasText(authHeader) || !authHeader.startsWith(BEARER_PREFIX)) {
        log.trace("[Filter] No JWT token found in 'Authorization: Bearer' header for path: {}", requestUri);
        filterChain.doFilter(request, response); // Continue chain without attempting JWT auth
        return;
      }

      // 3. Extract JWT Token String
      jwt = authHeader.substring(BEARER_PREFIX.length());
      log.trace("[Filter] Extracted JWT from header for path: {}", requestUri);

      // 4. Extract Username from Token (Initial validation happens here)
      // JwtUtils.extractUsername wraps parsing and will throw JwtException on failure
      username = jwtUtils.extractUsername(jwt);

      // 5. Check if username is extracted and no authentication exists in SecurityContext yet
      if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        log.debug("[Filter] Username '{}' extracted from JWT. Attempting to load UserDetails.", username);

        // 6. Load UserDetails via UserDetailsService
        // Throws UsernameNotFoundException if user doesn't exist
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

        log.debug("[Filter] UserDetails loaded for '{}'. Validating token...", username);
        // 7. Validate the token against the loaded UserDetails
        if (jwtUtils.validateToken(jwt, userDetails)) {
          // 8. Create Authentication Token (if JWT is valid)
          UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                  userDetails,
                  null, // Credentials (password) aren't needed for token-based auth
                  userDetails.getAuthorities() // Set user's roles/permissions
          );

          // 9. Set request details (IP address, session ID if any) onto the token
          authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

          // 10. Set the Authentication in the SecurityContext
          SecurityContextHolder.getContext().setAuthentication(authToken);
          log.debug("[Filter] User '{}' successfully authenticated via JWT. SecurityContext updated.", username);
        } else {
          // This branch might be less common if extractUsername/validateToken throw exceptions on failure.
          log.warn("[Filter] JWT token validation failed for user '{}' on path: {}", username, requestUri);
          // Explicitly clear context just in case, although it should be null here anyway
          SecurityContextHolder.clearContext();
        }
      } else if (username == null) {
        // Should ideally be caught by JwtException in extractUsername
        log.warn("[Filter] Could not extract username from provided JWT on path: {}", requestUri);
        SecurityContextHolder.clearContext();
      }
      // else: Authentication already exists in context, do nothing.

      // 11. Continue the filter chain
      filterChain.doFilter(request, response);

    } catch (ExpiredJwtException e) {
      // Specific handling for expired tokens
      log.warn("[Filter] JWT token expired for path [{}]: {}", requestUri, e.getMessage());
      SecurityContextHolder.clearContext(); // Ensure context is cleared on error
      // Delegate to global handler via resolver -> results in 410 Gone via TokenExpiredException mapping
      exceptionResolver.resolveException(request, response, null, new TokenExpiredException("JWT token has expired", e));
    } catch (JwtException e) {
      // Catch other JWT-related issues (malformed, signature invalid, unsupported)
      log.warn("[Filter] Invalid JWT token encountered for path [{}]: {}", requestUri, e.getMessage());
      SecurityContextHolder.clearContext();
      // Delegate to global handler -> results in 400 Bad Request via InvalidTokenException mapping
      exceptionResolver.resolveException(request, response, null, new InvalidTokenException("Invalid JWT token: " + e.getMessage(), e));
    } catch (UsernameNotFoundException e) {
      // User found in token subject, but not in database
      log.warn("[Filter] User specified in JWT not found in database for path [{}]: {}", requestUri, e.getMessage());
      SecurityContextHolder.clearContext();
      // Delegate to global handler -> results in 401 Unauthorized via AuthenticationException mapping (or custom if desired)
      exceptionResolver.resolveException(request, response, null, e);
    } catch (Exception e) {
      // Catch any other unexpected errors during filter processing
      log.error("[Filter] Unexpected error during JWT filter processing for path [{}]: {}", requestUri, e.getMessage(), e);
      SecurityContextHolder.clearContext();
      // Delegate to global handler -> results in 500 Internal Server Error
      exceptionResolver.resolveException(request, response, null, e);
    }
  }
}