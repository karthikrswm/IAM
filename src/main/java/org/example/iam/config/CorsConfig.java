// File: src/main/java/org/example/iam/config/CorsConfig.java
package org.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils; // Used for checking blank strings
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter; // Preferred filter for Spring Security integration
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer; // Keep for potential other MVC configs

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Configures Cross-Origin Resource Sharing (CORS) for the application.
 * <p>
 * CORS is a security mechanism that restricts web pages from making requests to a different
 * domain than the one that served the web page. This configuration allows specified origins
 * (typically frontend applications) to interact with the IAM API backend.
 * </p>
 * <p>
 * It primarily defines a {@link CorsFilter} bean, which integrates seamlessly with Spring Security
 * to handle CORS preflight (OPTIONS) requests and add necessary CORS headers to actual responses.
 * Configuration values (allowed origins, methods, headers, etc.) are read from
 * {@code application.properties}.
 * </p>
 */
@Configuration
@Slf4j
public class CorsConfig {

  // --- CORS Configuration Properties (from application.properties) ---

  // Allowed origins (e.g., "http://localhost:3000", "https://myfrontend.com")
  // Use an array to allow multiple origins. Default to empty if not set.
  @Value("${cors.allowed-origins:}")
  private String[] allowedOrigins;

  // Allowed HTTP methods (GET, POST, etc.)
  @Value("${cors.allowed-methods:GET,POST,PUT,DELETE,OPTIONS,PATCH}") // Common defaults
  private String[] allowedMethods;

  // Allowed HTTP headers (e.g., "Authorization", "Content-Type"). '*' allows all.
  @Value("${cors.allowed-headers:*}") // Default to allow all headers
  private String[] allowedHeaders;

  // Whether credentials (like cookies, authorization headers) are supported.
  @Value("${cors.allow-credentials:true}")
  private boolean allowCredentials;

  // Max age (in seconds) for caching preflight (OPTIONS) response by the browser.
  @Value("${cors.max-age:3600}") // Default to 1 hour (3600 seconds)
  private long maxAge;

  /**
   * Configures the {@link CorsFilter} bean. This filter is automatically picked up by
   * Spring Security (if present in the context) and applied early in the filter chain,
   * making it the recommended way to handle CORS when using Spring Security.
   *
   * @return A configured {@link CorsFilter} bean.
   */
  @Bean
  public CorsFilter corsFilter() {
    log.info("Initializing CORS filter configuration...");
    log.debug("Allowed Origins from properties: {}", Arrays.toString(allowedOrigins));
    log.debug("Allowed Methods from properties: {}", Arrays.toString(allowedMethods));
    log.debug("Allowed Headers from properties: {}", Arrays.toString(allowedHeaders));
    log.debug("Allow Credentials from properties: {}", allowCredentials);
    log.debug("Max Age from properties: {}", maxAge);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();

    // --- Apply Configuration ---
    config.setAllowCredentials(allowCredentials);

    // Handle Allowed Origins: Filter out blank entries and check if any valid origins remain.
    List<String> validOrigins = (allowedOrigins != null)
            ? Arrays.stream(allowedOrigins)
            .filter(StringUtils::hasText) // Remove blank/null strings
            .toList()
            : Collections.emptyList();

    if (!validOrigins.isEmpty()) {
      config.setAllowedOrigins(validOrigins);
      log.info("CORS Allowed Origins configured: {}", validOrigins);
    } else {
      log.warn("No valid CORS allowed origins specified in 'cors.allowed-origins' property. " +
              "Cross-origin requests from browsers might be blocked. Consider setting allowed origins " +
              "(e.g., http://localhost:3000 for local development).");
      // For local development ONLY, you might temporarily allow all origins (USE WITH CAUTION):
      // config.addAllowedOriginPattern("*"); // Allows all origins, less secure than specific list
      // log.warn("CORS allowing all origin patterns ('*') due to empty/missing configuration. NOT recommended for production.");
    }

    // Set allowed headers and methods from properties
    config.setAllowedHeaders(Arrays.asList(allowedHeaders));
    config.setAllowedMethods(Arrays.asList(allowedMethods));

    // Set max age for preflight response caching
    config.setMaxAge(maxAge);

    // --- Register Configuration ---
    // Apply this CORS configuration to all paths starting with "/api/"
    source.registerCorsConfiguration("/api/**", config);
    log.info("CORS configuration registered for path pattern '/api/**'");

    return new CorsFilter(source);
  }

  /**
   * Provides a {@link WebMvcConfigurer} bean. While not strictly necessary for CORS when using
   * the {@code CorsFilter} with Spring Security, this bean can be used for other global
   * MVC configurations like formatters, interceptors, view controllers, etc., if needed later.
   * Keeping it allows for future extensions without needing to add the bean later.
   *
   * @return A minimal {@link WebMvcConfigurer} instance.
   */
  @Bean
  public WebMvcConfigurer webMvcConfigurer() {
    log.debug("Registering basic WebMvcConfigurer bean.");
    return new WebMvcConfigurer() {
      // Currently no other MVC configurations are needed here.
      // Add custom formatters, interceptors, etc., within this anonymous class if required.
            /*
            @Override
            public void addFormatters(FormatterRegistry registry) {
                // Add custom formatters
            }

            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                // Add custom interceptors
            }
            */
    };
  }
}