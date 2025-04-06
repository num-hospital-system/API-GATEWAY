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
public class JwtAuthenticationGatewayFilter extends AbstractGatewayFilterFactory<JwtAuthenticationGatewayFilter.Config> {

    @Value("${jwt.secret}")
    private String jwtSecret;

    public JwtAuthenticationGatewayFilter() {
        super(Config.class);
        log.info("JwtAuthenticationGatewayFilter БИН ҮҮСГЭГДЛЭЭ.");
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
            
            log.info("JWT шүүлтүүр ажиллаж байна... ({})", this.getClass().getSimpleName());

            // JWT токен байгаа эсэхийг шалгах
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                log.warn("Authorization header олдсонгүй.");
                return onError(exchange, HttpStatus.UNAUTHORIZED, "Authorization header олдсонгүй");
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Bearer token олдсонгүй.");
                return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен олдсонгүй");
            }

            String jwt = authHeader.substring(7);
            Claims claims;
            try {
                claims = extractClaims(jwt);
            } catch (JwtException e) {
                 log.error("JWT токен задлахад алдаа гарлаа: {}", e.getMessage());
                 return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен хүчингүй/алдаатай байна");
            }
            
            if (claims == null) {
                 log.error("JWT токеноос claims гаргаж авч чадсангүй.");
                 return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен claims алдаатай байна");
            }

            // Хэрэглэгчийн мэдээллийг header-т нэмэх
            String userId = claims.getSubject();
            List<String> roles = claims.get("roles", List.class);
            log.info("Токеноос салгасан: UserID={}, Roles={}", userId, roles);

            if (userId == null || userId.isEmpty() || roles == null) {
                 log.error("JWT токен доторх userId эсвэл roles хоосон байна.");
                 return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен мэдээлэл дутуу байна");
            }

            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-ID", userId)
                    .header("X-User-Roles", String.join(",", roles))
                    .build();

            log.info("Дамжуулж буй header: X-User-ID={}, X-User-Roles={}", userId, String.join(",", roles));

            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Claims extractClaims(String jwt) throws JwtException {
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
        log.error("Authentication Error: Status={}, Message={}", status, message);
        exchange.getResponse().setStatusCode(status);
        // Optionally add response body here if needed
        // exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        // return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(...)));
        return exchange.getResponse().setComplete();
    }

    public static class Config {
        // Тохиргооны параметрүүд
    }
} 