
package net.pechorina.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
public class TokenProvider {
    private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    @Value("${security.authentication.jwt.systemId}")
    private String systemId;

    @Value("${security.authentication.jwt.secret}")
    private String secretKey;

    @Value("${security.authentication.jwt.tokenValidityInSeconds:86400}")
    private Long tokenValidityInSeconds;

    public String createToken(Authentication authentication, Integer ttl) {
        if (ttl == null) {
            ttl = tokenValidityInSeconds.intValue();
        }

        if (ttl < 1) {
            ttl = tokenValidityInSeconds.intValue();
        }

        List<String> authorities = authentication.getAuthorities()
                .stream()
                .map(authority -> authority.getAuthority())
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        return createToken(authentication.getName(), authorities, ttl);
    }

    public String createToken(String subject, List<String> authorities, Integer ttl) {
        Objects.requireNonNull(subject, "Subject must be not null");
        Objects.requireNonNull(authorities, "Authorities list must be not null");
        Objects.requireNonNull(ttl, "TTL must be not null");

        String authoritiesString = authorities.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.joining(","));

        LocalDateTime validity = LocalDateTime.now().plusSeconds(ttl);

        return Jwts.builder()
                .setSubject(subject)
                .claim("systemId", getSystemIdHash())
                .claim(AUTHORITIES_KEY, authoritiesString)
                .signWith(getKey())
                .setExpiration(Date.from(validity.atZone(ZoneId.systemDefault()).toInstant()))
                .compact();
    }

    private String getSystemIdHash() {
        return DigestUtils.sha256Hex(secretKey + systemId);
    }

    private Key getKey() {
        Key key;
        try {
            key = Keys.hmacShaKeyFor(secretKey.getBytes());
        } catch (WeakKeyException e) {
            log.error("Weak wmd.security.authentication.jwt.secret key, increase it's length", e);
            throw new RuntimeException(e);
        }

        return key;
    }

    public Authentication getAuthentication(String token) {
        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build();

        Claims claims = parser.parseClaimsJws(token).getBody();

        String principal = claims.getSubject();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.asList(claims.get(AUTHORITIES_KEY).toString().split(",")).stream()
                        .map(authority -> new SimpleGrantedAuthority(authority))
                        .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public boolean validateToken(String authToken) {
        if (authToken == null || authToken.trim().isEmpty()) {
            log.info("Empty JWT token");
            return false;
        }

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(getKey())
                .setAllowedClockSkewSeconds(60L)
                .require("systemId", getSystemIdHash())
                .build();

        Jws<Claims> claims = parser.parseClaimsJws(authToken);

        if (log.isTraceEnabled()) {
            log.trace("JWT token body: {}", claims.getBody());
        }

        return true;
    }
}
