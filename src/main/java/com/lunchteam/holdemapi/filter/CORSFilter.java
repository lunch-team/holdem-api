package com.lunchteam.holdemapi.filter;

import com.lunchteam.holdemapi.properties.CorsProperties;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 외부에서 접근가능하도록 CORS 허용
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CORSFilter implements Filter {

    private final CorsProperties properties;

    public CORSFilter(CorsProperties properties) {
        this.properties = properties;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String host = "*";
        if (!properties.isALL()) {
            host = properties.getIP() + ":" + properties.getPORT();
        }

        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse
                .setHeader("Access-Control-Allow-Origin", host);
        httpServletResponse
                .setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        httpServletResponse
                .setHeader("Access-Control-Max-Age", "3600");
        httpServletResponse
                .setHeader("Access-Control-Allow-Headers", "*");
        httpServletResponse
                .setHeader("Access-Control-Allow-Credentials", "true");
        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) {
        log.debug("CORS Filter init");
    }

    @Override
    public void destroy() {
        log.debug("CORS Filter destroy");
    }
}
