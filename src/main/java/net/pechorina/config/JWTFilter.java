package net.pechorina.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.MalformedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Filters incoming requests and installs a Spring Security principal if a header corresponding to a valid user is
 * found.
 */
public class JWTFilter extends GenericFilterBean {

    private final Logger log = LoggerFactory.getLogger(JWTFilter.class);

    private TokenProvider tokenProvider;

    public JWTFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        try {
            HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
            String jwt = resolveToken(httpServletRequest);
            if (StringUtils.hasText(jwt)) {
                if (this.tokenProvider.validateToken(jwt)) {
                    Authentication authentication = this.tokenProvider.getAuthentication(jwt);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (ExpiredJwtException eje) {
            log.info(
                    "Error: Expired JWT token for user {} - {} - {}",
                    eje.getClaims().getSubject(),
                    eje.getMessage(),
                    getUserInfo(servletRequest)
            );

            ((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (io.jsonwebtoken.security.SecurityException eje) {
            log.info("Error: Security error: {} - {}", eje.getMessage(), getUserInfo(servletRequest));

            ((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (IncorrectClaimException e) {
            log.info("Error: Incorrect claim for user {} - {} - {}", e.getClaims().getSubject(), e.getMessage(),
                    getUserInfo(servletRequest)
            );

            ((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (MalformedJwtException e) {
            log.info("Error: Malformed JWT token for {}", getUserInfo(servletRequest));

            ((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    public static String resolveToken(HttpServletRequest request) {

        // First locate JWT token in header
        String bearerToken = request.getHeader(JWTConfigurer.AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // Then try to find it in the request's parameters
        String paramToken = request.getParameter(JWTConfigurer.AUTHORIZATION_PARAM);
        if (paramToken != null && StringUtils.hasText(paramToken)) {
            return paramToken;
        }

        // Then in cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            return Arrays.stream(cookies)
                    .filter(Objects::nonNull)
                    .filter(cookie -> JWTConfigurer.AUTHORIZATION_COOKIE.equalsIgnoreCase(cookie.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        return null;
    }

    private UserInfo getUserInfo(ServletRequest request) {
        UserInfo userInfo = new UserInfo();
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;
            userInfo.setUserAgent(httpServletRequest.getHeader("User-Agent"));
            userInfo.setIpAddress(
                    Optional.ofNullable(httpServletRequest.getHeader("X-Real-IP")).orElse(request.getRemoteAddr())
            );
        }
        return userInfo;
    }

    class UserInfo {
        private String userAgent;
        private String ipAddress;

        public UserInfo setUserAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public UserInfo setIpAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        @Override
        public String toString() {
            return "{" +
                    "userAgent='" + userAgent + '\'' +
                    ", ipAddress='" + ipAddress + '\'' +
                    '}';
        }
    }
}
