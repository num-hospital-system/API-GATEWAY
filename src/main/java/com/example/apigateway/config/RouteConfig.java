package com.example.apigateway.config; // Uncommented package declaration

import com.example.apigateway.filter.JwtAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    private static final Logger log = LoggerFactory.getLogger(RouteConfig.class);

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        log.info("RouteLocator БИН ҮҮСГЭЖ, ЗАМУУДЫГ ТОДОРХОЙЛЖ БАЙНА...");
        return builder.routes()
                .route("auth-service", r -> r
                        .path("/api/auth/**")
                        .filters(f -> f.stripPrefix(1)
                        .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://52.77.99.18:8081"))
                // .route("authorization-service", r -> r
                // .path("/api/authorization/**")
                //         .filters(f -> f
                //                 .stripPrefix(1)
                //                 .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                //         .uri("http://52.77.99.18:8082"))
                .build();
    }
}