package com.lunchteam.holdemapi.filter;


import com.lunchteam.holdemapi.security.TokenProvider;
import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * {@link OncePerRequestFilter} 인터페이스를 구현하기 때문에 요청받을 때 단 한번 실행된다
 */
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";

    private final TokenProvider tokenProvider;


    /**
     * Request Header 에서 토큰 정보를 꺼내오기
     *
     * @param request HttpServletRequest
     * @return bearerToken
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * 실제 필터링 로직
     * <p>
     * JWT의 인증 정보를 현재 쓰레드의 {@link org.springframework.security.core.context.SecurityContext}에 저장하는
     * 역할
     * <p>
     * Request Header에서 Access Token을 꺼내고 유저 정보를 꺼내 SecurityContext에 저장
     * <p>
     * 가입 / 로그인 / 재발급을 제외한 모든 Request 요청은 이 필터를 거치기 때문에 토큰 정보가 없거나 유효하지 않으면 정상적으로 수행되지 않음
     * <p>
     * 요청이 정상적으로 Controller까지 도착했다면 SecurityContext에 Member Id가 존재한다는 것이 보장됨
     * <p>
     * 탈퇴로 인해 Member Id가 DB에 없는 경우 등 예외 상황은 Service 단에서 고려해야 함
     *
     * @param request     HttpServletRequest
     * @param response    HttpServletResponse
     * @param filterChain FilterChain
     */
    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request,
                                    @Nonnull HttpServletResponse response,
                                    @Nonnull FilterChain filterChain) throws ServletException, IOException {
        // 1. Request Header 에서 토큰을 꺼냄
        String jwt = resolveToken(request);

        // 2. validateToken 으로 토큰 유효성 검사
        // 정상 토큰이면 해당 토큰으로 Authentication 을 가져와서 SecurityContext 에 저장
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }
}
