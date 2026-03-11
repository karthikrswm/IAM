// File: src/main/java/org/example/iam/config/SecurityConfig.java
package org.example.iam.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.filter.CsrfTokenGenerationFilter;
import org.example.iam.filter.JwtAuthenticationFilter;
import org.example.iam.repository.DatabaseClientRegistrationRepository;
import org.example.iam.repository.DatabaseRelyingPartyRegistrationRepository;
import org.example.iam.security.*;
import org.example.iam.security.saml.ForceAuthnContextSamlRequestCustomizer;
import org.example.iam.service.CustomOAuth2UserService;
import org.example.iam.service.CustomSaml2AuthenticationConverter;
import org.example.iam.service.CustomSaml2UserService;
import org.example.iam.security.DelegatingLogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager; // <<< ADDED Import
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler; // <<< ADDED Import
import org.springframework.security.web.authentication.AuthenticationSuccessHandler; // <<< ADDED Import
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;


/**
 * Main Spring Security configuration class for the IAM application.
 * <p>
 * Enables web security, method-level security (@PreAuthorize, @Secured), and configures:
 * <ul>
 * <li>HTTP security rules (public endpoints, authentication requirements).</li>
 * <li>Session management (using Redis-backed sessions).</li>
 * <li>Authentication providers (DaoAuthenticationProvider for JWT).</li>
 * <li>JWT filter integration.</li>
 * <li>Custom exception handling (AuthenticationEntryPoint, AccessDeniedHandler).</li>
 * <li>OAuth2 Login configuration using dynamic DB registrations, JIT, and custom handlers.</li>
 * <li>SAML2 Login configuration using dynamic DB registrations and custom converter for JIT.</li>
 * <li>CORS configuration integration (via CorsFilter bean).</li>
 * <li>CSRF Protection using Cookie-based repository suitable for SPAs, including SessionAuthenticationStrategy.</li>
 * </ul>
 * </p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

  private static final String[] PUBLIC_ENDPOINTS = {
      "/api/v1/auth/**",
      "/error",
      "/v3/api-docs/**",
      "/swagger-ui/**",
      "/swagger-ui.html",
      "/actuator/health",
      "/login/saml2/sso/**",
      "/login/oauth2/code/**",
      "/saml2/service-provider-metadata/**",
      "/logout/saml2/slo/**"
  };

  // --- Injected Dependencies ---
  // ... (Most injections unchanged) ...
  private final UserDetailsService userDetailsService;
  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final CsrfTokenGenerationFilter csrfTokenGenerationFilter;
  private final DatabaseClientRegistrationRepository databaseClientRegistrationRepository;
  private final DatabaseRelyingPartyRegistrationRepository databaseRelyingPartyRegistrationRepository;
  private final CustomOAuth2UserService customOAuth2UserService;
  private final CustomSaml2UserService customSaml2UserService; // Used by converter bean
  //    private final CustomSaml2AuthenticationConverter customSaml2AuthenticationConverter; // Used by provider bean
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final CustomAccessDeniedHandler customAccessDeniedHandler;
  //    @Qualifier("delegatingLogoutSuccessHandler") // Use new bean name
  private final DelegatingLogoutSuccessHandler delegatingLogoutSuccessHandler;
  // OAuth2 Handlers
  private final AuthenticationSuccessHandler customOAuth2AuthenticationSuccessHandler;
  private final AuthenticationFailureHandler customOAuth2AuthenticationFailureHandler;
  // SAML Handlers (Assuming beans are defined via @Component or @Bean below)
//    @Qualifier("customSamlAuthenticationSuccessHandler") // Qualify injection if multiple beans exist
  private final AuthenticationSuccessHandler customSamlAuthenticationSuccessHandler;
  //    @Qualifier("customSamlAuthenticationFailureHandler")
  private final AuthenticationFailureHandler customSamlAuthenticationFailureHandler;
  // SAML Provider
//    private final OpenSaml4AuthenticationProvider samlAuthenticationProvider;
  // SAML Request Resolver/Repo (Use interfaces, Spring finds beans)
//    private final Saml2AuthenticationRequestResolver saml2AuthenticationRequestResolver;
  // Inject the new customizer bean
  private final ForceAuthnContextSamlRequestCustomizer forceAuthnContextSamlRequestCustomizer; // <<< ADDED Injection
  // CORS Filter
  private final CorsFilter corsFilter;

  @Value("${security.password.encoder.strength}")
  private int bCryptStrength;

  @Bean
  @Order(1)
  public SecurityFilterChain filterChain(HttpSecurity http,
      CsrfTokenRepository csrfTokenRepository,
      @Lazy SessionAuthenticationStrategy sessionAuthenticationStrategy,
      Saml2AuthenticationRequestResolver saml2AuthenticationRequestResolver,
      OpenSaml4AuthenticationProvider samlAuthenticationProvider
  ) throws Exception {
    log.info("Configuring main SecurityFilterChain with SAML (JIT + Custom Handlers)...");
    CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();

    http
        // ... (Standard Filters: cors, csrf, sessionManagement, authorizeHttpRequests) ...
        .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
        .csrf(csrf -> csrf.csrfTokenRequestHandler(requestHandler)
                          .csrfTokenRepository(csrfTokenRepository)
                          .sessionAuthenticationStrategy(sessionAuthenticationStrategy)
                          .ignoringRequestMatchers(
                              AntPathRequestMatcher.antMatcher("/api/v1/auth/**"),
                              AntPathRequestMatcher.antMatcher("/saml2/authenticate/**"),
                              AntPathRequestMatcher.antMatcher("/logout/saml2/slo/**"), // <<< ADD THIS LINE
                              // Add a custom matcher to ignore CSRF if the Authorization header contains a Bearer token
                              new RequestMatcher() {
                                @Override
                                public boolean matches(HttpServletRequest request) {
                                  String authHeader = request.getHeader("Authorization");
                                  return authHeader != null && authHeader.startsWith("Bearer ");
                                }
                              }
                          ))
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
        .authorizeHttpRequests(
            auth -> auth.requestMatchers(PUBLIC_ENDPOINTS).permitAll().anyRequest().authenticated())

        // Authentication Providers
        .authenticationProvider(authenticationProvider()) // DAO
        .authenticationProvider(samlAuthenticationProvider) // SAML

        // Standard Filters
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(csrfTokenGenerationFilter, JwtAuthenticationFilter.class)
        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler))

        // OAuth2 Config
        .oauth2Login(oauth2 -> oauth2.clientRegistrationRepository(clientRegistrationRepository())
            .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
            .successHandler(customOAuth2AuthenticationSuccessHandler)
            .failureHandler(customOAuth2AuthenticationFailureHandler))

        // --- Configure SAML2 Login using custom handlers ---
        .saml2Login(saml2 -> saml2
            .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository()) // Use DB repo
            .authenticationManager(
                new ProviderManager(samlAuthenticationProvider)) // Use SAML provider bean
            .authenticationRequestResolver(saml2AuthenticationRequestResolver)
            // Use default (but configurable) resolver bean
            // <<< Configure Custom Handlers >>>
            .successHandler(customSamlAuthenticationSuccessHandler) // Custom SAML Success Handler
            .failureHandler(customSamlAuthenticationFailureHandler) // Custom SAML Failure Handler
        )
        .saml2Logout(saml2 -> {
          saml2.logoutUrl("/logout/saml2/slo/{registrationId}");
          // Use default resolvers/validators for now. Configure here later if needed.
          log.debug("Enabling SAML 2.0 Single Logout processing filters.");
        })
        .logout(logout -> logout
                // Define the URL(s) that trigger logout processing
                // .logoutUrl("/logout") // Default POST /logout
                // Or use a request matcher for more control
                .logoutRequestMatcher(
                    new AntPathRequestMatcher("/api/v1/auth/logout", "POST")) // Example API logout path
                // Configure the RENAMED custom success handler
                .logoutSuccessHandler(delegatingLogoutSuccessHandler)
                .invalidateHttpSession(false) // Custom handler invalidates session
                .clearAuthentication(true) // Clear security context
            // Let handler manage cookies explicitly if needed, or set here:
            // .deleteCookies("IAMSESSID", "XSRF-TOKEN")
        );
    ;

    log.info(
        "SecurityFilterChain configuration complete. SAML configured with JIT converter and custom success/failure handlers.");
    return http.build();
  }

  // --- Bean Definitions for Security Components ---

  // == SAML Related Beans ==

  @Bean // Provider using custom JIT converter
  public OpenSaml4AuthenticationProvider samlAuthenticationProvider(
      CustomSaml2AuthenticationConverter customSaml2AuthenticationConverter) {
    OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
    authenticationProvider.setResponseAuthenticationConverter(customSaml2AuthenticationConverter);
    log.info(
        "Configuring OpenSaml4AuthenticationProvider bean with CustomSaml2AuthenticationConverter.");
    return authenticationProvider;
  }

  @Bean // Custom JIT converter
  public CustomSaml2AuthenticationConverter customSaml2AuthenticationConverter() {
    return new CustomSaml2AuthenticationConverter(customSaml2UserService);
  }

  // Update the default resolver bean definition to use the injected customizer
  @Bean
  public Saml2AuthenticationRequestResolver saml2AuthenticationRequestResolver() {
    OpenSaml4AuthenticationRequestResolver resolver = new OpenSaml4AuthenticationRequestResolver(
        databaseRelyingPartyRegistrationRepository);
    // <<< Use the injected customizer bean >>>
    resolver.setAuthnRequestCustomizer(forceAuthnContextSamlRequestCustomizer);
    log.info(
        "Configuring default OpenSaml4AuthenticationRequestResolver bean with ForceAuthnContextSamlRequestCustomizer.");
    return resolver;
  }


  @Bean
  public CsrfTokenRepository csrfTokenRepository() {
    CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
    repository.setCookieName("XSRF-TOKEN");
    return repository;
  }

  @Bean
  public SessionAuthenticationStrategy sessionAuthenticationStrategy(
      CsrfTokenRepository csrfTokenRepository) {
    log.info(
        "Configuring CompositeSessionAuthenticationStrategy with ChangeSessionId and Csrf strategies.");
    return new CompositeSessionAuthenticationStrategy(Arrays.asList(
        new ChangeSessionIdAuthenticationStrategy(),
        new CsrfAuthenticationStrategy(csrfTokenRepository)
    ));
  }

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    return databaseClientRegistrationRepository;
  }

  @Bean
  public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
    return databaseRelyingPartyRegistrationRepository;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    log.info("Creating BCryptPasswordEncoder bean with strength: {}", bCryptStrength);
    return new BCryptPasswordEncoder(bCryptStrength);
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig)
      throws Exception {
    log.debug("Retrieving AuthenticationManager bean.");
    return authConfig.getAuthenticationManager();
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(passwordEncoder());
    log.info("Configuring DaoAuthenticationProvider bean.");
    return authProvider;
  }

  @Bean
  public DefaultAuthenticationEventPublisher authenticationEventPublisher() {
    log.debug("Configuring DefaultAuthenticationEventPublisher bean.");
    return new DefaultAuthenticationEventPublisher();
  }
}
