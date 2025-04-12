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

@Slf4j
@Component
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
            String path = request.getURI().getPath();
            log.info("==== ШАЛГАЖ БУЙ ЗАМ: {} ====", path);

            // Нэвтрэх болон бүртгүүлэх хүсэлтүүдийг шалгахгүй алгасах
            // /auth/login эсвэл /api/auth/login гэсэн хоёр замын аль нэгийг нь шалгана
            if (path.endsWith("/auth/login") || 
                path.endsWith("/auth/register") ||
                path.endsWith("/api/auth/login") || 
                path.endsWith("/api/auth/register")) {
                log.info("Нэвтрэх/Бүртгүүлэх зам учир JWT шалгахгүй алгасаж байна: {}", path);
                return chain.filter(exchange);
            }

            log.info("JWT шүүлтүүр эхэллээ...");

            // JWT токен шалгах
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            log.info("Authorization header: {}", authHeader);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Bearer token олдсонгүй эсвэл буруу формат");
                return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен олдсонгүй");
            }

            String jwt = authHeader.substring(7);
            log.info("JWT токен олдлоо: {}", jwt.substring(0, Math.min(10, jwt.length())) + "...");

            try {
                Claims claims = extractClaims(jwt);
                String userId = claims.getSubject();
                List<String> roles = claims.get("roles", List.class);

                if (roles == null) {
                    roles = List.of();
                }

                log.info("JWT мэдээлэл:");
                log.info("User ID: {}", userId);
                log.info("Roles: {}", roles);

                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header(HttpHeaders.AUTHORIZATION, authHeader) 
                    .header("X-User-ID", userId)
                    .header("X-User-Roles", String.join(",", roles))
                    .build();

                return chain.filter(exchange.mutate().request(modifiedRequest).build());

            } catch (Exception e) {
                log.error("JWT боловсруулахад алдаа гарлаа: {}", e.getMessage());
                return onError(exchange, HttpStatus.UNAUTHORIZED, "JWT токен хүчингүй байна");
            }
        };
    }

    // private boolean isValidToken(String jwt) {
    //     try {
    //         Jwts.parserBuilder()
    //                 .setSigningKey(getSigningKey())
    //                 .build()
    //                 .parseClaimsJws(jwt);
    //         return true;
    //     } catch (JwtException e) {
    //         log.error("JWT токен шалгахад алдаа гарлаа: {}", e.getMessage());
    //         return false;
    //     }
    // }

    private Claims extractClaims(String jwt) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
        } catch (Exception e) {
            log.error("JWT claims задлахад алдаа: {}", e.getMessage());
            throw e;
        }
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