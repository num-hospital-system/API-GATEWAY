package com.example.apigateway.config;

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
                        // .uri("http://localhost:8081"))
                        .uri("http://52.77.99.18:8081"))
// ҮҮНИЙГ АШИГЛАХ БОЛ https://github.com/num-hospital-system/num_auth.git ҮҮНИЙ user_detail_register-г ./mvnw spring-boot:run гээд ажиллуулаарай
// ҮҮНИЙГ АШИГЛАХ БОЛ https://github.com/num-hospital-system/num_auth.git ҮҮНИЙ user_detail_register-г ./mvnw spring-boot:run гээд ажиллуулаарай
                .route("user_detail_register", r -> r 
                        .path("/api/user-details/**")
                        .filters(f -> f.stripPrefix(1)
                        .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://localhost:8083"))
                // Add route for ExaminationService
                .route("ExaminationService", r -> r
                        .path("/api/examination/**" , "/api/examination/diagnosis/**" , "/api/examination/prescriptions/**" , "/api/examination/survey/**" , "/api/examination/instruction/**")
                        .filters(f -> f
                        .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://localhost:8084"))
                // .route("authorization-service", r -> r
                // .path("/api/authorization/**")
                //         .filters(f -> f
                //                 .stripPrefix(1)
                //                 .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                //         .uri("http://52.77.99.18:8082"))
                .route("userapi", r -> r
                        .path("/api/customer/registration/**")
                        .filters(f -> f
                                .stripPrefix(1)
                                .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
                        .uri("http://54.251.178.246:8080"))
                .build();
    }
}
