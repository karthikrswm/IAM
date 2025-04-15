// File: src/main/java/org/example/iam/config/SecurityConfig.java
package org.example.iam.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.filter.JwtAuthenticationFilter;
import org.example.iam.repository.DatabaseClientRegistrationRepository;
import org.example.iam.repository.DatabaseRelyingPartyRegistrationRepository;
import org.example.iam.security.CustomAccessDeniedHandler; // Import custom handler
import org.example.iam.security.JwtAuthenticationEntryPoint; // Import custom entry point
import org.example.iam.service.CustomOAuth2UserService;
// Import CustomSaml2UserService if integrating SAML JIT later
// import org.example.iam.service.CustomSaml2UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
// Removed unused OAuth2 user service imports
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// Import CorsFilter if configuring CORS via filter bean (recommended)
import org.springframework.web.filter.CorsFilter;


/**
 * Main Spring Security configuration class for the IAM application.
 * <p>
 * Enables web security, method-level security (@PreAuthorize, @Secured), and configures:
 * <ul>
 * <li>HTTP security rules (public endpoints, authentication requirements).</li>
 * <li>Session management (stateless for JWT).</li>
 * <li>Authentication providers (DaoAuthenticationProvider for JWT).</li>
 * <li>JWT filter integration.</li>
 * <li>Custom exception handling (AuthenticationEntryPoint, AccessDeniedHandler).</li>
 * <li>OAuth2 Login configuration using dynamic DB registrations.</li>
 * <li>SAML2 Login configuration using dynamic DB registrations.</li>
 * <li>CORS configuration integration (via CorsFilter bean).</li>
 * </ul>
 * </p>
 */
@Configuration
@EnableWebSecurity // Enables Spring Security's web security support.
// Enables method-level security annotations like @PreAuthorize, @PostAuthorize, @Secured.
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

  /**
   * Defines URL patterns accessible without authentication.
   * Includes auth endpoints, error pages, OpenAPI docs, health checks, and SSO callbacks.
   */
  private static final String[] PUBLIC_ENDPOINTS = {
          "/api/v1/auth/**",                 // Login, verification, password reset etc.
          "/error",                          // Spring Boot default error page
          "/v3/api-docs/**",                 // OpenAPI specification
          "/swagger-ui/**",                  // Swagger UI resources
          "/swagger-ui.html",                // Swagger UI entry point
          "/actuator/health",                // Basic health check endpoint
          // --- SSO Callbacks ---
          "/login/saml2/sso/**",             // SAML Assertion Consumer Service endpoint pattern
          "/login/oauth2/code/**",           // OAuth2 Authorization Code callback pattern
          "/saml2/service-provider-metadata/**" // SAML SP Metadata endpoint pattern
  };

  // --- Injected Dependencies ---
  private final UserDetailsService userDetailsService; // For DaoAuthenticationProvider
  private final JwtAuthenticationFilter jwtAuthenticationFilter; // Custom JWT filter
  private final DatabaseClientRegistrationRepository databaseClientRegistrationRepository; // OAuth2 repo
  private final DatabaseRelyingPartyRegistrationRepository databaseRelyingPartyRegistrationRepository; // SAML repo
  private final CustomOAuth2UserService customOAuth2UserService; // Handles OAuth2 JIT
  // private final CustomSaml2UserService customSaml2UserService; // Inject if implementing SAML JIT

  // Custom handlers for authentication/authorization exceptions
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final CustomAccessDeniedHandler customAccessDeniedHandler;

  // Optional: Inject CorsFilter if configured as a bean in CorsConfig
  private final CorsFilter corsFilter;

  // Password encoder strength from properties
  @Value("${security.password.encoder.strength}")
  private int bCryptStrength;

  /**
   * Defines the main security filter chain applied to HTTP requests.
   * Configures CSRF, CORS, session management, authorization rules, filters, and exception handling.
   * Uses modern lambda DSL style for configuration.
   *
   * @param http HttpSecurity object to configure.
   * @return The configured SecurityFilterChain.
   * @throws Exception If configuration fails.
   */
  @Bean
  // Use @Order(1) or adjust as needed if multiple SecurityFilterChains exist.
  @Order(1)
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    log.info("Configuring main SecurityFilterChain...");

    http
            // Add CorsFilter early if configured as a bean (preferred over http.cors(Customizer.withDefaults()))
            // Ensures CORS headers are handled correctly, especially for preflight OPTIONS requests before security checks.
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
            //.cors(Customizer.withDefaults()) // Alternatively, use this if CorsFilter bean isn't defined

            // Disable CSRF protection as we are using stateless JWT authentication.
            // CSRF protection is primarily for stateful session-based applications.
            .csrf(AbstractHttpConfigurer::disable)

            // Configure session management to be STATELESS.
            // No HTTP session will be created or used by Spring Security.
            .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Configure authorization rules for HTTP requests.
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(PUBLIC_ENDPOINTS).permitAll() // Allow public access to defined endpoints.
                    .anyRequest().authenticated() // Require authentication for all other requests.
            )

            // Register the DaoAuthenticationProvider.
            .authenticationProvider(authenticationProvider())

            // Add the custom JWT filter before the standard UsernamePasswordAuthenticationFilter.
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

            // --- Custom Exception Handling ---
            // Configure custom handlers for authentication and authorization errors.
            .exceptionHandling(exceptions -> exceptions
                    // Entry point called when authentication is required but not provided, or fails early.
                    .authenticationEntryPoint(jwtAuthenticationEntryPoint) // Handles 401 Unauthorized
                    // Handler called when an authenticated user lacks permission for a resource.
                    .accessDeniedHandler(customAccessDeniedHandler)        // Handles 403 Forbidden
            )

            // --- OAuth2 Login Configuration ---
            .oauth2Login(oauth2 -> oauth2
                            // Use our custom repository to load client registrations dynamically from the DB.
                            .clientRegistrationRepository(clientRegistrationRepository())
                            // Configure the user info endpoint processing.
                            .userInfoEndpoint(userInfo -> userInfo
                                    // Use our custom service to handle JIT user provisioning after successful OAuth2 auth.
                                    .userService(customOAuth2UserService)
                            )
                    // Optional: Configure success/failure handlers for OAuth2 login if needed.
                    // .successHandler(customOAuth2SuccessHandler)
                    // .failureHandler(customOAuth2FailureHandler)
            )

            // --- SAML2 Login Configuration ---
            .saml2Login(saml2 -> saml2
                            // Use our custom repository to load relying party registrations dynamically from the DB.
                            .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository())
                    // TODO: Configure SAML JIT Integration Point
                    // Full SAML JIT provisioning requires more than just configuration here.
                    // It typically involves:
                    // 1. A custom Saml2AuthenticationConverter to extract attributes after successful authentication.
                    // 2. Invoking a service (like CustomSaml2UserService) from the converter or a custom
                    //    AuthenticationProvider to find/create the local user based on SAML attributes.
                    // 3. Ensuring the final Authentication object contains the *local* UserDetails.
                    // Example placeholder for where customization might occur:
                    // .authenticationConverter(customSamlAuthenticationConverter(customSaml2UserService))
            );

    log.info("SecurityFilterChain configuration complete.");
    return http.build();
  }

  // --- Bean Definitions for Security Components ---

  /**
   * Provides the repository for fetching OAuth2 client registrations (from the database).
   * This bean is referenced by the oauth2Login configuration.
   *
   * @return The custom ClientRegistrationRepository implementation.
   */
  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    // Ensure the correct bean (DatabaseClientRegistrationRepository) is returned.
    // Autowiring handles this via the constructor injection.
    return databaseClientRegistrationRepository;
  }

  /**
   * Provides the repository for fetching SAML2 relying party registrations (from the database).
   * This bean is referenced by the saml2Login configuration.
   *
   * @return The custom RelyingPartyRegistrationRepository implementation.
   */
  @Bean
  public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
    // Ensure the correct bean (DatabaseRelyingPartyRegistrationRepository) is returned.
    return databaseRelyingPartyRegistrationRepository;
  }

  /**
   * Defines the PasswordEncoder bean used for hashing and verifying passwords.
   * Uses BCrypt with a configurable strength factor.
   *
   * @return A BCryptPasswordEncoder instance.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    log.info("Creating BCryptPasswordEncoder bean with strength: {}", bCryptStrength);
    return new BCryptPasswordEncoder(bCryptStrength);
  }

  /**
   * Exposes the AuthenticationManager as a bean. Required for manual authentication calls
   * (e.g., in the AuthService for JWT login).
   *
   * @param authConfig The AuthenticationConfiguration provided by Spring Security.
   * @return The configured AuthenticationManager.
   * @throws Exception If retrieval fails.
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    log.debug("Retrieving AuthenticationManager bean.");
    return authConfig.getAuthenticationManager();
  }

  /**
   * Defines the primary AuthenticationProvider used for username/password authentication (JWT flow).
   * Uses DaoAuthenticationProvider configured with our custom UserDetailsService and PasswordEncoder.
   *
   * @return A configured DaoAuthenticationProvider.
   */
  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService); // Set custom UserDetailsService
    authProvider.setPasswordEncoder(passwordEncoder()); // Set the password encoder
    log.info("Configuring DaoAuthenticationProvider bean.");
    return authProvider;
  }

  /**
   * Defines an AuthenticationEventPublisher bean to publish authentication success/failure events.
   * Useful for integrating with auditing or other listeners that react to authentication events.
   * Spring Boot auto-configures listeners for common events (like BadCredentialsEvent).
   *
   * @return A DefaultAuthenticationEventPublisher instance.
   */
  @Bean
  public DefaultAuthenticationEventPublisher authenticationEventPublisher() {
    log.debug("Configuring DefaultAuthenticationEventPublisher bean.");
    return new DefaultAuthenticationEventPublisher();
  }
}