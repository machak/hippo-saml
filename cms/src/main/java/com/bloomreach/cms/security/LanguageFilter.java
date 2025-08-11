package com.bloomreach.cms.security;

import com.google.common.base.Strings;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.hippoecm.frontend.PluginApplication;
import org.hippoecm.frontend.session.PluginUserSession;
import org.hippoecm.frontend.session.UserSession;
import org.hippoecm.frontend.util.WebApplicationHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Locale;
import java.util.TimeZone;

public class LanguageFilter implements Filter {
    private static final String LOCALE_COOKIE = "loc";
    private static final String CONSOLE_LOCALE = "en";
    private static final String TIMEZONE_COOKIE = "tzcookie";

    private static final Logger log = LoggerFactory.getLogger(LanguageFilter.class);


    @Override
    public void doFilter(final ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        final HttpServletRequest servletRequest = (HttpServletRequest) request;
        final HttpSession session = servletRequest.getSession();
        final PluginUserSession userSession = PluginUserSession.get();

        if (userSession != null && isSetTzLng(session)) {
            try {
                setPreferences(servletRequest, userSession);
            } catch (Exception e) {
                log.error("Error setting user language and timezone", e);
            }
        }
    }

    private void setPreferences(HttpServletRequest servletRequest, PluginUserSession userSession) {
        log.debug("setting user language and time zone from a cookie");
        String cookieLocale;
        if (isConsole()) {
            log.debug("Console request, locale is '{}'", CONSOLE_LOCALE);
            cookieLocale = CONSOLE_LOCALE;
        } else {
            cookieLocale = getCookieValue(servletRequest, LOCALE_COOKIE);
        }
        if (!Strings.isNullOrEmpty(cookieLocale)) {
            log.debug("Found cookieLocale {}", cookieLocale);
            userSession.setLocale(getLocale(cookieLocale));
        }
        // time zone:

        final String cookieTimeZone = getCookieValue(servletRequest, TIMEZONE_COOKIE);
        if (isTimeZoneValid(cookieTimeZone)) {
            final TimeZone timeZone = TimeZone.getTimeZone(cookieTimeZone);
            UserSession.get().getClientInfo().getProperties().setTimeZone(timeZone);
        }
    }

    private boolean isTimeZoneValid(String cookieTimeZone) {
        if (Strings.isNullOrEmpty(cookieTimeZone)) {
            return  false;
        }
        // add additional validation if needed
        return true;
    }


    protected static boolean isConsole() {
        return WebApplicationHelper.getApplicationName().equals(PluginApplication.PLUGIN_APPLICATION_VALUE_CONSOLE);
    }

    private boolean isSetTzLng(HttpSession session) {
        if (session == null) {
            return false;
        }
        final Boolean attribute = (Boolean) session.getAttribute(LoginSuccessFilter.SET_TZ_LANG);
        return attribute != null && attribute;
    }

    private Locale getLocale(final String value) {
        if (value.equals(Locale.CHINESE.getLanguage())) {
            // always use simplified Chinese, Wicket does not know Chinese without a country
            return Locale.SIMPLIFIED_CHINESE;
        }
        return new Locale(value);
    }

    protected String getCookieValue(final HttpServletRequest request, final String cookieName) {
        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (final Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}

