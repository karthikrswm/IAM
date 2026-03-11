// File: src/main/java/org/example/iam/filter/CsrfTokenGenerationFilter.java
package org.example.iam.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * A filter that generates and sets a CSRF token for authenticated users.
 * <p>
 * This filter is designed to be executed after the JwtAuthenticationFilter to ensure
 * that a CSRF token is generated and set in the cookie for the first authenticated API call
 * when using JWT authentication.
 * </p>
 */
@Component
@Slf4j
public class CsrfTokenGenerationFilter extends OncePerRequestFilter {

    private final CsrfTokenRepository csrfTokenRepository;

    public CsrfTokenGenerationFilter(@org.springframework.context.annotation.Lazy CsrfTokenRepository csrfTokenRepository) {
        this.csrfTokenRepository = csrfTokenRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Get the current authentication from the security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Only generate a CSRF token if the user is authenticated
        if (authentication != null && authentication.isAuthenticated()) {
            // Check if a CSRF token already exists in the request
            CsrfToken existingToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

            if (existingToken == null) {
                // Generate a new CSRF token and set it in the response
                CsrfToken csrfToken = csrfTokenRepository.generateToken(request);
                csrfTokenRepository.saveToken(csrfToken, request, response);
                log.debug("[CsrfFilter] Generated and set CSRF token for authenticated user");
            }
        }

        // Continue the filter chain
        filterChain.doFilter(request, response);
    }
}
