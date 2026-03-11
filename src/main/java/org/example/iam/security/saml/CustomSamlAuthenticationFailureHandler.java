// File: src/main/java/org/example/iam/security/saml/CustomSamlAuthenticationFailureHandler.java
package org.example.iam.security.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.api.ApiError;
import org.example.iam.constant.ApiErrorMessages;
import org.example.iam.constant.AuditEventType; // <<< ADDED Import
import org.example.iam.service.AuditEventService; // <<< ADDED Import
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID; // <<< ADDED Import

/**
 * Custom AuthenticationFailureHandler for SAML 2.0 Logins.
 * Prevents redirects, logs audit event, and returns a standardized ApiError JSON response.
 */
@Component("customSamlAuthenticationFailureHandler")
@RequiredArgsConstructor
@Slf4j
public class CustomSamlAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper; // For writing JSON response
    private final AuditEventService auditEventService; // <<< ADDED Dependency

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String requestUri = request.getRequestURI();
        // Try to extract SAML details for logging, default otherwise
        String errorCode = "saml_authentication_error";
        String samlErrorMessage = exception.getMessage();
        String actor = "UNKNOWN_SAML_USER"; // Cannot determine actor on failure typically
        UUID orgId = null; // Cannot easily determine Org ID on failure usually

        // Log initial failure
        log.warn("[SAML Failure Handler] SAML Authentication Failure for path '{}': {}", requestUri, exception.getMessage(), exception);

        HttpStatus status = HttpStatus.UNAUTHORIZED; // Default 401
        String responseMessage = ApiErrorMessages.AUTHENTICATION_FAILED + " (SAML)"; // Default message

        if (exception instanceof Saml2AuthenticationException samlException) {
            Saml2Error samlError = samlException.getSaml2Error();
            if (samlError != null) {
                errorCode = StringUtils.hasText(samlError.getErrorCode()) ? samlError.getErrorCode() : "saml_error_unknown_code";
                samlErrorMessage = StringUtils.hasText(samlError.getDescription()) ? samlError.getDescription() : exception.getMessage();

                // Map known error codes from 6.2.4 Saml2ErrorCodes
                switch (errorCode) {
                    case Saml2ErrorCodes.INVALID_SIGNATURE:
                    case Saml2ErrorCodes.INVALID_ASSERTION:
                    case Saml2ErrorCodes.INVALID_RESPONSE:
                    case Saml2ErrorCodes.MALFORMED_RESPONSE_DATA:
                    case Saml2ErrorCodes.INVALID_DESTINATION:
                    case Saml2ErrorCodes.INVALID_ISSUER:
                        status = HttpStatus.BAD_REQUEST; break;
                    case Saml2ErrorCodes.DECRYPTION_ERROR:
                    case Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR:
                        status = HttpStatus.INTERNAL_SERVER_ERROR; break;
                    case Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND:
                        status = HttpStatus.INTERNAL_SERVER_ERROR; break;
                    // Add other cases from response #94 if needed...
                    default: status = HttpStatus.UNAUTHORIZED; break;
                }
                responseMessage = String.format("SAML Authentication Failed [%s]: %s", errorCode, samlErrorMessage);
            } else {
                responseMessage = samlException.getMessage(); // Use exception message if no Saml2Error
            }
        } else if (exception.getCause() instanceof org.opensaml.messaging.handler.MessageHandlerException) {
            responseMessage = "SAML message processing error: " + exception.getMessage();
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        } else {
            // Handle other AuthenticationExceptions
            responseMessage = exception.getMessage();
            status = HttpStatus.UNAUTHORIZED;
        }

        // --- Log Audit Event --- <<< ADDED
        auditEventService.logFailureEvent(
                AuditEventType.LOGIN_FAILURE, // Use standard failure type
                "SAML login failed.",
                actor, // Actor is unknown here
                "SAML_ASSERTION", // Target resource type
                null, // Target resource ID (no user ID yet)
                orgId, // Org ID likely unknown
                String.format("Error Code: %s, Message: %s", errorCode, samlErrorMessage) // Details
        );

        log.warn("[SAML Failure Handler] Responding with status {} and message: {}", status, responseMessage);
        ApiError apiError = new ApiError(status, responseMessage, requestUri);
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try (OutputStream out = response.getOutputStream()) {
            objectMapper.writeValue(out, apiError);
        } catch (IOException e) {
            log.error("[SAML Failure Handler] Error writing {} response for path '{}'", status, requestUri, e);
            throw e;
        }
    }
}