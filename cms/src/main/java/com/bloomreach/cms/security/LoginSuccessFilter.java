package com.bloomreach.cms.security;

import org.hippoecm.frontend.model.UserCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.jcr.SimpleCredentials;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

public class LoginSuccessFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(LoginSuccessFilter.class);

    private static final String SSO_USER_STATE = SSOUserState.class.getName();

    private static final ThreadLocal<SSOUserState> userStateHolder = new ThreadLocal<SSOUserState>();

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("doFilter LoginSuccessFilter");

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!authentication.isAuthenticated()) {
            log.debug("User not authenticated");
            chain.doFilter(request, response);
            return;
        }

        // Check if the user already has a SSO user state stored in HttpSession before.
        HttpSession session = ((HttpServletRequest) request).getSession();

        SSOUserState userState = (SSOUserState) session.getAttribute(SSO_USER_STATE);

        if (userState == null || !userState.getSessionId().equals(session.getId())) {
            try {
                final String username = extractUserName(authentication);
                if (username == null) {
                    log.warn("name is null in SAML response");
                    chain.doFilter(request, response);
                    return;
                }
                final SimpleCredentials credentials = new SimpleCredentials(username, "DUMMY".toCharArray());
                credentials.setAttribute(SSOUserState.SAML_ID, username);
                userState = new SSOUserState(new UserCredentials(credentials), session.getId());
                session.setAttribute(SSO_USER_STATE, userState);


            } catch (Exception e) {
                log.debug("Error authenticating with SAML", e);
                chain.doFilter(request, response);
                return;
            }

        }

        // If the user has a valid SSO user state, then
        // set a JCR Credentials as request attribute (named by FQCN of UserCredentials class).
        // Then the CMS application will use the JCR credentials passed through this request attribute.
        if (userState.getSessionId().equals(session.getId())) {
            request.setAttribute(UserCredentials.class.getName(), userState.getCredentials());
        }

        try {
            userStateHolder.set(userState);
            chain.doFilter(request, response);
        } finally {
            userStateHolder.remove();
        }

    }

    private String extractUserName(final Authentication authentication) {
        // TODO add your own logic in here
        return authentication.getName();
    }

    /**
     * Get current <code>SSOUserState</code> instance from the current thread local context.
     */
    static SSOUserState getCurrentSSOUserState() {
        return userStateHolder.get();
    }

    @Override
    public void destroy() {

    }
}
