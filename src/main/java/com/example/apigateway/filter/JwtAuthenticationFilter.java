package com.example.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.List;

@Component
@Slf4j
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Value("${jwt.secret}")
    private String jwtSecret;

    public JwtAuthenticationFilter() {
        super(Config.class);
        log.info("JwtAuthenticationFilter БИН ҮҮСГЭГДЛЭЭ.");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            log.info("Шалгаж буй зам: {}", request.getURI().getPath());

            // Бүртгэлийн хүсэлтийг шүүлтээс хасах
            if (request.getURI().getPath().contains("/api/auth/login") ||
                request.getURI().getPath().contains("/api/auth/register")) {
                log.info("Нэвтрэх/бүртгүүлэх замыг алгасаж байна.");
                return chain.filter(exchange);
            }
            
            log.info("JWT шүүлтүүр ажиллаж байна...");

            // JWT токен байгаа эсэхийг шалгах
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Authorization header олдсонгүй");
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен олдсонгүй");
            }

            String jwt = authHeader.substring(7);
            if (!isValidToken(jwt)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен хүчингүй байна");
            }

            // Хэрэглэгчийн мэдээллийг header-т нэмэх
            Claims claims = extractClaims(jwt);
            String userId = claims.getSubject();
            List<String> roles = claims.get("roles", List.class);
            log.info("Токеноос салгасан ролууд: {}", roles);

            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-ID", userId)
                    .header("X-User-Roles", String.join(",", roles != null ? roles : List.of()))
                    .build();

            log.info("Дамжуулж буй header: X-User-ID={}, X-User-Roles={}", userId, String.join(",", roles != null ? roles : List.of()));

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private boolean isValidToken(String jwt) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(jwt);
            return true;
        } catch (JwtException e) {
            log.error("JWT токен шалгахад алдаа гарлаа: {}", e.getMessage());
            return false;
        }
    }

    private Claims extractClaims(String jwt) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        // Тохиргооны параметрүүд
    }
} 