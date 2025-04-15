// File: src/main/java/org/example/iam/config/SessionConfig.java
package org.example.iam.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.HeaderHttpSessionIdResolver;
import org.springframework.session.web.http.HttpSessionIdResolver;

/**
 * Configuration for managing HTTP sessions using Redis via Spring Session Data Redis.
 * <p>
 * While the primary authentication mechanism in this application is stateless JWT,
 * Redis-backed sessions can be useful for:
 * <ul>
 * <li>Managing state during external authentication flows like OAuth2 or SAML redirects.</li>
 * <li>Storing temporary user-specific data that doesn't fit well into JWT claims.</li>
 * <li>Supporting potential future features that might require server-side session state.</li>
 * </ul>
 * The {@link EnableRedisHttpSession @EnableRedisHttpSession} annotation enables the integration,
 * configuring session timeout and a Redis keyspace namespace.
 * </p>
 */
@Configuration
// Enables Redis-backed HTTP Sessions.
// - maxInactiveIntervalInSeconds: Sets the session timeout (e.g., 1800 = 30 minutes).
// - redisNamespace: Creates a keyspace in Redis (e.g., "iam:session:") to avoid key collisions.
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800, redisNamespace = "iam:session")
@Slf4j
public class SessionConfig {

  /**
   * Configures the connection factory for interacting with Redis.
   * <p>
   * This implementation relies on Spring Boot's auto-configuration. It automatically reads
   * Redis connection details (host, port, password, database index, SSL settings, etc.)
   * from properties defined under the {@code spring.data.redis.*} prefix
   * in {@code application.properties}. It uses Lettuce as the underlying Redis client library.
   * </p>
   * <p>
   * For manual configuration (e.g., connecting to a specific Redis instance not defined
   * in properties), you would create and configure a {@code RedisStandaloneConfiguration} or
   * {@code RedisSentinelConfiguration} / {@code RedisClusterConfiguration} and pass it
   * to the {@code LettuceConnectionFactory} constructor.
   * </p>
   *
   * @return A {@link LettuceConnectionFactory} bean configured based on application properties.
   */
  @Bean
  public LettuceConnectionFactory redisConnectionFactory() {
    log.info("Configuring LettuceConnectionFactory for Redis sessions (using spring.data.redis.* properties).");
    // Spring Boot auto-configures this bean based on properties.
    // No manual configuration needed here if properties are set correctly.
    return new LettuceConnectionFactory();
  }

  /*
   * --- Optional Session ID Resolution Configuration ---
   * By default, Spring Session uses cookies (typically named "SESSION") to track sessions.
   * If you need to resolve the session ID from a header (e.g., for purely API-driven clients
   * that don't handle cookies well), you can uncomment and configure the HttpSessionIdResolver bean.
   * However, for standard web flows (like OAuth2/SAML redirects) and potential future browser-based
   * interactions, cookie-based resolution is generally preferred.
   */
  // @Bean
  // public HttpSessionIdResolver httpSessionIdResolver() {
  //     log.info("Configuring HeaderHttpSessionIdResolver using 'X-Auth-Token' header for session ID resolution.");
  //     // Example: Use the 'X-Auth-Token' header instead of cookies.
  //     return HeaderHttpSessionIdResolver.xAuthToken();
  //     // Alternative: Use a custom header name:
  //     // return new HeaderHttpSessionIdResolver("X-Custom-Session-Id");
  // }

  /*
   * --- Optional Cookie Customization ---
   * If using the default cookie-based session tracking, you can customize the cookie's
   * properties (name, security flags, domain, path, SameSite attribute) by defining a
   * CookieSerializer bean.
   */
  // @Bean
  // public CookieSerializer cookieSerializer() {
  //     log.info("Configuring custom DefaultCookieSerializer for session cookies.");
  //     DefaultCookieSerializer serializer = new DefaultCookieSerializer();
  //     serializer.setCookieName("IAMSESSID"); // Custom cookie name
  //     serializer.setUseHttpOnlyCookie(true);  // Recommended for security (prevents client-side script access)
  //     serializer.setUseSecureCookie(true);    // Recommended for production (requires HTTPS)
  //     serializer.setSameSite("Strict");      // Recommended ('Strict' or 'Lax') to mitigate CSRF
  //     // serializer.setDomainName("example.com"); // Set cookie domain if needed
  //     // serializer.setCookiePath("/");           // Set cookie path if needed
  //     return serializer;
  // }

}