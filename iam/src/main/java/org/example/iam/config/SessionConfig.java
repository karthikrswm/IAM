// File: src/main/java/org/example/iam/config/SessionConfig.java
package org.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
// Correct import for the annotation
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;

/**
 * Configuration for managing HTTP sessions using Redis via Spring Session Data Redis.
 * <p>
 * Configures Redis connection, session timeout, namespace, and session ID resolution strategy
 * (Header-based by default in this configuration). Cookie-based options are also configured
 * but commented out.
 * </p>
 */
@Configuration
// Enables Redis-backed HTTP Sessions.
// Reads timeout from 'spring.session.timeout' property (e.g., "30m", "1800s").
// Reads namespace from 'spring.session.redis.namespace' property (e.g., "iam:session").
// Defaults are handled by Spring Session if properties are not explicitly set.
@EnableRedisHttpSession // Reads properties directly
@Slf4j
public class SessionConfig {

  // Reference properties for logging purposes
  @Value("${spring.session.timeout:30m}") // Reference property for logging/verification
  private String sessionTimeout;

  @Value("${spring.session.redis.namespace:iam:session}") // Reference property for logging/verification
  private String redisNamespace;


  /**
   * Configures the connection factory for interacting with Redis.
   * <p>
   * Relies on Spring Boot's auto-configuration based on spring.data.redis.* properties.
   * </p>
   *
   * @return A {@link LettuceConnectionFactory} bean.
   */
  @Bean
  public LettuceConnectionFactory redisConnectionFactory() {
    log.info("Configuring LettuceConnectionFactory for Redis sessions (using spring.data.redis.* properties).");
    // Log the effective values read by @EnableRedisHttpSession (or defaults)
    log.info("Spring Session Redis Namespace: '{}', Default Timeout: '{}'", redisNamespace, sessionTimeout);
    // Spring Boot auto-configures this bean based on properties.
    return new LettuceConnectionFactory();
  }

  /**
   * Configures the strategy for resolving the session ID.
   * Uses the 'X-Auth-Token' HTTP header by default.
   * Comment out this bean to revert to the default Cookie-based resolution.
   *
   * @return An HttpSessionIdResolver instance configured for header-based resolution.
   */
//  @Bean
//  public HttpSessionIdResolver httpSessionIdResolver() {
//    log.warn("Configuring HeaderHttpSessionIdResolver using 'X-Auth-Token' header for session ID resolution. " +
//            "Clients must send the session ID in this header.");
//    // Use the standard 'X-Auth-Token' header.
//    return HeaderHttpSessionIdResolver.xAuthToken();
//    // Alternative: Use a custom header name:
//    // return new HeaderHttpSessionIdResolver("X-Custom-Session-Id");
//  }

  /**
   * Configures custom properties for the session cookie if cookie-based resolution is used.
   * This bean is defined but will only be used if the httpSessionIdResolver bean (above) is commented out.
   *
   * @return A configured CookieSerializer instance.
   */
  @Bean
  public CookieSerializer cookieSerializer() {
    log.info("Defining custom DefaultCookieSerializer bean (will be used ONLY if HeaderHttpSessionIdResolver is disabled).");
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    // NOTE: These settings only apply if HeaderHttpSessionIdResolver is NOT active.
    String cookieName = "IAMSESSID"; // Define name locally for logging
    String sameSite = "Lax";       // Define setting locally for logging
    boolean useSecure = false;     // Define setting locally for logging (SET TO true FOR PROD HTTPS)
    boolean useHttpOnly = true;    // Define setting locally for logging

    serializer.setCookieName(cookieName);
    serializer.setUseHttpOnlyCookie(useHttpOnly);
    serializer.setUseSecureCookie(useSecure);
    serializer.setSameSite(sameSite);
    // serializer.setDomainName("example.com");
    serializer.setCookiePath("/");

    // Corrected logging - Log the values we *set* or intend to set
    log.debug("Custom cookie serializer defined: Name={}, HttpOnly={}, Secure={}, SameSite={}",
            cookieName,
            useHttpOnly,
            useSecure, // Log the boolean value directly
            sameSite
    );
    return serializer;
  }

}