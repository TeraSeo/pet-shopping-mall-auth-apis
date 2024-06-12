package com.shoppingmall.auth.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

    private final SecretKey key;

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] bytes = DatatypeConverter.parseBase64Binary(secretKey);
        this.key = Keys.hmacShaKeyFor(
                bytes
        );
    }

    private final Logger LOGGER = LoggerFactory.getLogger(JwtTokenProvider.class);

    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보 없는 토큰 입니다.");
        }

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(), "", authorities);

        LOGGER.debug("getAuthentication Success");

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public JwtToken generateToken(Authentication authentication) {

        String authorities = authentication.getAuthorities()
                .stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String accessToken = createAccessToken(authentication, authorities);
        String refreshToken = createRefreshToken(authentication, authorities);

        LOGGER.debug("generate Token success");

        return JwtToken.builder()
//                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public String createAccessToken(Authentication authentication, String authorities) {
        String accessToken = Jwts.builder()
                .signWith(key)
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .compact();

        return accessToken;
    }

    public String createRefreshToken(Authentication authentication, String authorities) {
        String refreshToken = Jwts.builder()
                .signWith(key)
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 72))
                .compact();

        return refreshToken;
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            LOGGER.debug("valid date: " + claims.getBody().getExpiration());
            boolean isValid = claims.getBody().getExpiration().after(new Date());
            if (isValid) {
                LOGGER.debug("token is valid");
                return true;
            }
            LOGGER.debug("token is expired");
            return false;

        } catch (io.jsonwebtoken.security.SecurityException e) {

        } catch (ExpiredJwtException e) {

        } catch (UnsupportedJwtException e) {

        } catch (IllegalArgumentException e) {

        }
        return false;
    }

    private Claims parseClaims(String accessToken) {
        try {
            LOGGER.debug("parse claim success");
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public String resolveAccessToken(HttpServletRequest request) {
        LOGGER.debug("resolving access token");
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            LOGGER.debug("correct Bearer token");
            return bearerToken.substring(7);
        }
        return null;
    }
}
