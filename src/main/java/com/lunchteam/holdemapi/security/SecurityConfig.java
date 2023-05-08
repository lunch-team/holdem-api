package com.lunchteam.holdemapi.security;

import com.lunchteam.holdemapi.properties.CorsProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Spring Security 2 -> 3 마이그레이션
 * 문서 참조 <a href="https://nahwasa.com/entry/%EC%8A%A4%ED%94%84%EB%A7%81-%EB%B6%80%ED%8A%B8-20%EC%97%90%EC%84%9C-30-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0-%EB%A7%88%EC%9D%B4%EA%B7%B8%EB%A0%88%EC%9D%B4%EC%85%98-%EB%B3%80%EA%B2%BD%EC%A0%90">마이그레이션</a>
 */
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsProperties properties;
    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        List<String> permitUrl = new ArrayList<>();
        if (properties.isALL()) {
            permitUrl.add("/**");
        } else {
            permitUrl.add("/auth/**");
            permitUrl.add("/api/connectionTest");
            permitUrl.add("/stat/**");
            permitUrl.add("/chat/**");
            permitUrl.add("/ws-stomp/**");
            permitUrl.add("/file/**");
            permitUrl.add("/menu/get*");
        }
        return http.csrf().disable()

                // exception handling
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
                // 시큐리티는 기본적으로 세션을 사용하지만
                // 세션을 사용하지 않기 때문에 세션 설정을 Stateless 로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // 로그인, 회원가입 API 는 토큰이 없는 상태에서 요청이 들어오기 때문에 permitAll 설정
                .and()
                .authorizeHttpRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest)
                .permitAll()
                .requestMatchers(
                        permitUrl.toArray(new String[0])
                )
                .permitAll()
                .anyRequest().authenticated()   // 나머지 API 는 전부 인증 필요
                .and()
                .apply(new JwtSecurityConfig(tokenProvider))
                .and()
                .build();
    }
}
