// File: src/main/java/org/example/iam/filter/JwtAuthenticationFilter.java
package org.example.iam.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException; // Catch broader JWT exceptions
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
// Removed RequiredArgsConstructor as we modify the constructor
import lombok.extern.slf4j.Slf4j;
import org.example.iam.exception.InvalidTokenException;
import org.example.iam.exception.TokenExpiredException;
import org.example.iam.security.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.lang.NonNull; // Use Spring's NonNull for clarity
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext; // <<< ADDED Import
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy; // <<< ADDED Import
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository; // <<< ADDED Import
import org.springframework.security.web.context.SecurityContextRepository; // <<< ADDED Import
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
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
 * <li>If valid, creates an {@link UsernamePasswordAuthenticationToken}, sets it in the
 * {@link SecurityContextHolder}, **and explicitly saves the context to the session repository**.</li> // <<< Updated Doc
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
  private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
  private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
  private final CsrfTokenRepository csrfTokenRepository;

  @Autowired
  @Qualifier("handlerExceptionResolver")
  private HandlerExceptionResolver exceptionResolver;

  public JwtAuthenticationFilter(JwtUtils jwtUtils, 
                            @Qualifier("userDetailsService") UserDetailsService userDetailsService,
                            @org.springframework.context.annotation.Lazy CsrfTokenRepository csrfTokenRepository) {
    this.jwtUtils = jwtUtils;
    this.userDetailsService = userDetailsService;
    this.csrfTokenRepository = csrfTokenRepository;
  }


  /**
   * Processes the incoming request to perform JWT authentication *only if* no authentication
   * already exists in the security context.
   * Saves security context explicitly if JWT authentication succeeds.
   * ... (Original JavaDoc) ...
   */
  @Override
  protected void doFilterInternal(
          @NonNull HttpServletRequest request,
          @NonNull HttpServletResponse response,
          @NonNull FilterChain filterChain)
          throws ServletException, IOException {

    final String requestUri = request.getRequestURI();

    try {
      // <<< MODIFIED: Check for existing auth FIRST >>>
      if (securityContextHolderStrategy.getContext().getAuthentication() == null) {
        // No authentication found yet (e.g., from session), try JWT header
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(authHeader) && authHeader.startsWith(BEARER_PREFIX)) {
          // Header found, attempt JWT processing
          final String jwt = authHeader.substring(BEARER_PREFIX.length());
          log.trace("[Filter] No existing auth. Extracted JWT from header for path: {}", requestUri);
          final String username = jwtUtils.extractUsername(jwt); // Can throw JwtException

          if (username != null) {
            log.debug("[Filter] Username '{}' extracted from JWT. Attempting to load UserDetails.", username);
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username); // Throws UsernameNotFoundException

            log.debug("[Filter] UserDetails loaded for '{}'. Validating token...", username);
            if (jwtUtils.validateToken(jwt, userDetails)) {
              UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                      userDetails, null, userDetails.getAuthorities()
              );
              authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

              SecurityContext context = securityContextHolderStrategy.createEmptyContext();
              context.setAuthentication(authToken);
              securityContextHolderStrategy.setContext(context);
              securityContextRepository.saveContext(context, request, response); // Explicitly save context

              // Generate and set CSRF token
              CsrfToken csrfToken = csrfTokenRepository.generateToken(request);
              csrfTokenRepository.saveToken(csrfToken, request, response);
              log.debug("[Filter] User '{}' successfully authenticated via JWT header. SecurityContext updated AND CSRF token generated.", username);
            } else {
              log.warn("[Filter] JWT token validation failed for user '{}' on path: {}", username, requestUri);
              // Don't set context, proceed for potential exception handling later
            }
          } else {
            log.warn("[Filter] Could not extract username from provided JWT on path: {}", requestUri);
            // Don't set context
          }
        } else {
          log.trace("[Filter] No existing auth and no JWT header found for path: {}. Proceeding anonymously.", requestUri);
        }
      } else {
        log.trace("[Filter] SecurityContext already contains authentication (likely from session). Skipping JWT processing for path: {}", requestUri);
      }

      // Continue the filter chain regardless of whether JWT was processed (unless exception occurred below)
      filterChain.doFilter(request, response);

    } catch (ExpiredJwtException e) {
      log.warn("[Filter] JWT token expired for path [{}]: {}", requestUri, e.getMessage());
      securityContextHolderStrategy.clearContext(); // Clear context on error
      // Attempt saving cleared context? Maybe not needed as error is being delegated.
      // securityContextRepository.saveContext(securityContextHolderStrategy.getContext(), request, response);
      exceptionResolver.resolveException(request, response, null, new TokenExpiredException("JWT token has expired", e));
    } catch (JwtException e) {
      log.warn("[Filter] Invalid JWT token encountered for path [{}]: {}", requestUri, e.getMessage());
      securityContextHolderStrategy.clearContext();
      exceptionResolver.resolveException(request, response, null, new InvalidTokenException("Invalid JWT token: " + e.getMessage(), e));
    } catch (UsernameNotFoundException e) {
      log.warn("[Filter] User specified in JWT not found in database for path [{}]: {}", requestUri, e.getMessage());
      securityContextHolderStrategy.clearContext();
      exceptionResolver.resolveException(request, response, null, e);
    } catch (Exception e) {
      log.error("[Filter] Unexpected error during JWT filter processing for path [{}]: {}", requestUri, e.getMessage(), e);
      securityContextHolderStrategy.clearContext();
      exceptionResolver.resolveException(request, response, null, e);
    }
    // Note: If an exception occurred and was resolved, the filter chain *might* not continue depending on the resolver.
    // Our delegation to HandlerExceptionResolver typically stops the chain here by writing an error response.
  }
}
