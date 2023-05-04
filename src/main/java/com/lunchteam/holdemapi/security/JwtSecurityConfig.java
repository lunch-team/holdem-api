package com.lunchteam.holdemapi.security;

import com.lunchteam.holdemapi.filter.JwtFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 직접 만든 TokenProvider와 JwtFilter를 SecurityConfig에 적용할 때 사용
@RequiredArgsConstructor
public class JwtSecurityConfig extends
        SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final TokenProvider tokenProvider;

    /**
     * TokenProvider를 주입받아 JwtFilter를 통해 Security 로직에 필터 등록
     *
     * @param builder {@link HttpSecurity}
     */
    @Override
    public void configure(HttpSecurity builder) {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        // 직접 만든 customFilter를 Security Filter 앞에 추가
        builder.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
