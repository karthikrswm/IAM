// File: src/main/java/org/example/iam/config/SecurityConfig.java
package org.example.iam.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.filter.CsrfTokenGenerationFilter;
import org.example.iam.filter.JwtAuthenticationFilter;
import org.example.iam.repository.DatabaseClientRegistrationRepository;
import org.example.iam.repository.DatabaseRelyingPartyRegistrationRepository;
import org.example.iam.security.CustomAccessDeniedHandler;
import org.example.iam.security.CustomOAuth2AuthenticationFailureHandler; // <<< ADDED Import
import org.example.iam.security.CustomOAuth2AuthenticationSuccessHandler; // <<< ADDED Import
import org.example.iam.security.JwtAuthenticationEntryPoint;
import org.example.iam.service.CustomOAuth2UserService;
import org.example.iam.service.CustomSaml2AuthenticationConverter;
import org.example.iam.service.CustomSaml2UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager; // <<< ADDED Import
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
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
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
          "/saml2/service-provider-metadata/**"
  };

  // --- Injected Dependencies ---
  private final UserDetailsService userDetailsService;
  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final CsrfTokenGenerationFilter csrfTokenGenerationFilter;
  private final DatabaseClientRegistrationRepository databaseClientRegistrationRepository;
  private final DatabaseRelyingPartyRegistrationRepository databaseRelyingPartyRegistrationRepository;
  private final CustomOAuth2UserService customOAuth2UserService;
  private final CustomSaml2UserService customSaml2UserService;

  // Custom handlers for authentication/authorization exceptions
  private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
  private final CustomAccessDeniedHandler customAccessDeniedHandler;

  // Custom handlers for OAuth2 flow <<< ADDED
  private final AuthenticationSuccessHandler customOAuth2AuthenticationSuccessHandler;
  private final AuthenticationFailureHandler customOAuth2AuthenticationFailureHandler;

  private final CorsFilter corsFilter;

  @Value("${security.password.encoder.strength}")
  private int bCryptStrength;

  /**
   * Defines the main security filter chain applied to HTTP requests.
   *
   * @param http HttpSecurity object to configure.
   * @param csrfTokenRepository The configured CsrfTokenRepository bean.
   * @param sessionAuthenticationStrategy The configured SessionAuthenticationStrategy bean.
   * @param customSaml2AuthenticationConverter The converter for SAML JIT.
   * @return The configured SecurityFilterChain.
   * @throws Exception If configuration fails.
   */
  @Bean
  @Order(1)
  public SecurityFilterChain filterChain(HttpSecurity http,
                                         CsrfTokenRepository csrfTokenRepository,
                                         @org.springframework.context.annotation.Lazy SessionAuthenticationStrategy sessionAuthenticationStrategy,
                                         CustomSaml2AuthenticationConverter customSaml2AuthenticationConverter
  ) throws Exception {
    log.info("Configuring main SecurityFilterChain...");
    CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();

    http
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
            .csrf(csrf -> csrf
                    .csrfTokenRequestHandler(requestHandler)
                    .csrfTokenRepository(csrfTokenRepository)
                    .sessionAuthenticationStrategy(sessionAuthenticationStrategy)
                    .ignoringRequestMatchers(
                            AntPathRequestMatcher.antMatcher("/api/v1/auth/**")
                    )

            )
            .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            )
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                    .anyRequest().authenticated()
            )
            .authenticationProvider(authenticationProvider())
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(csrfTokenGenerationFilter, JwtAuthenticationFilter.class)
            .exceptionHandling(exceptions -> exceptions
                    .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                    .accessDeniedHandler(customAccessDeniedHandler)
            )
            // --- OAuth2 Login Configuration ---
            .oauth2Login(oauth2 -> oauth2
                    .clientRegistrationRepository(clientRegistrationRepository())
                    .userInfoEndpoint(userInfo -> userInfo
                            .userService(customOAuth2UserService)
                    )
                    .successHandler(customOAuth2AuthenticationSuccessHandler) // <<< ADDED Success Handler
                    .failureHandler(customOAuth2AuthenticationFailureHandler) // <<< ADDED Failure Handler
            )
//            .formLogin(Customizer.withDefaults());
//            // --- SAML2 Login Configuration ---
            .saml2Login(saml2 -> saml2
                    .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository())
                    .authenticationManager(new ProviderManager(openSaml4AuthenticationProvider(customSaml2AuthenticationConverter)))
            );


    log.info("SecurityFilterChain configuration complete. OAuth2 Handlers configured.");
    return http.build();
  }


  // --- Bean Definitions for Security Components --- (Existing beans remain the same)

  @Bean
  public OpenSaml4AuthenticationProvider openSaml4AuthenticationProvider(CustomSaml2AuthenticationConverter customSaml2AuthenticationConverter) {
    OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
    authenticationProvider.setResponseAuthenticationConverter(customSaml2AuthenticationConverter);
    log.info("Configuring OpenSaml4AuthenticationProvider with CustomSaml2AuthenticationConverter.");
    return authenticationProvider;
  }

  @Bean
  public CustomSaml2AuthenticationConverter customSaml2AuthenticationConverter(CustomSaml2UserService customSaml2UserService) {
    return new CustomSaml2AuthenticationConverter(customSaml2UserService);
  }

  @Bean
  public CsrfTokenRepository csrfTokenRepository() {
    CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
    repository.setCookieName("XSRF-TOKEN");
    return repository;
  }

  @Bean
  public SessionAuthenticationStrategy sessionAuthenticationStrategy(CsrfTokenRepository csrfTokenRepository) {
    log.info("Configuring CompositeSessionAuthenticationStrategy with ChangeSessionId and Csrf strategies.");
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
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
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
