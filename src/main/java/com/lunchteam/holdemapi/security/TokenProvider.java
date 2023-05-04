package com.lunchteam.holdemapi.security;

import com.lunchteam.holdemapi.security.dto.TokenDto;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * JWT에 관련된 암호화, 복호화, 검증 로직은 모두 여기서 이루어짐
 */
@Slf4j
@Component
public class TokenProvider {

    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "bearer";
    private static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;            // 30분
    private static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7;  // 7일

    private final Key key;

    /**
     * application.yml에 정의해놓은 jwt.secret 값을 가져와 JWT를 만들 때 사용하는 암호화 키값 생성
     *
     * @param secretKey from Properties
     */
    public TokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * 유저 정보를 넘겨받아 Access Token, Refresh Token 생성
     * <p>
     * 넘겨받은 유저 정보의 authentication.getName() 메소드가 username을 가져옴
     * <p>
     * AccessToken에는 유저와 권한 정보를 담고 RefreshToken에는 아무 정보도 담지 않음
     *
     * @param authentication {@link Authentication}
     * @return Token
     */
    public TokenDto generateTokenDto(Authentication authentication) {
        // 권한 조회
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        long now = (new Date()).getTime();

        // Access Token 생성
        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration(accessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        // Refresh Token 생성
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + REFRESH_TOKEN_EXPIRE_TIME))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        return TokenDto.builder()
                .grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * JWT를 복호화하여 토큰에 있는 정보를 꺼낸다.
     * <p>
     * AccessToken에만 유저 정보를 담기 때문에 명시적으로 accessToken을 매개변수로 받아온다.
     * <p>
     * RefreshToken에는 아무 정보 없이 만료일자만 담음
     * <p>
     * UserDetails 객체를 생성하여 {@link UsernamePasswordAuthenticationToken}형태로 리턴
     * <p>
     * 이 절차는 {@link org.springframework.security.core.context.SecurityContext}가 {@link
     * Authentication} 객체를 저장하기 때문에 어쩔 수 없음
     *
     * @param accessToken Token
     * @return Authentication
     */
    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get(AUTHORITIES_KEY) == null) {
            throw new RuntimeException("No Authentication");
        }

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    /**
     * Valid Token
     * <p>
     * Jwts 모듈이 알아서 Exception을 처리
     *
     * @param token String Token
     * @return Bool
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.warn("Wrong JWT Sign.");
        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT");
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT");
        } catch (IllegalArgumentException e) {
            log.warn("Wrong JWT");
        }

        return false;
    }

    /**
     * 만료된 토큰에서도 정보를 꺼내기 위해 분리
     *
     * @param accessToken Token
     * @return Claims
     */
    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
