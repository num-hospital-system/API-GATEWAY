package com.example.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.addAllowedOrigin("*"); 
        corsConfig.addAllowedMethod("*");
        corsConfig.addAllowedHeader("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .cors(corsSpec -> corsSpec.configurationSource(source))
            .authorizeExchange(exchanges -> exchanges
                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll() 
                .pathMatchers("/api/auth/**").permitAll()
                .pathMatchers("/api/user-details/**").permitAll()
                .pathMatchers("/api/examination/**").permitAll()
                .pathMatchers("/api/examination/diagnosis/**").permitAll()
                .pathMatchers("/api/examination/prescriptions/**").permitAll()
                .pathMatchers("/api/examination/survey/**").permitAll()
                .pathMatchers("/api/examination/instruction/**").permitAll()
                .pathMatchers("/api/**").authenticated()
                .anyExchange().permitAll()
            )
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable);
        return http.build();
    }
}