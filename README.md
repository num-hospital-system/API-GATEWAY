# API-GATEWAY

## API Gateway ашиглах заавар

API Gateway нь бүх микросервисүүдийн хүсэлтийг хүлээн авч, холбогдох үйлчилгээ рүү дамжуулах гол хаалга юм. Энэхүү API Gateway нь JWT токен дээр суурилсан аутентикейшн систем ашигладаг.

### Одоогийн тохируулагдсан үйлчилгээнүүд

1. **Auth Service** - `/api/auth/**` замаар дамжуулагдана
   - Хандах хаяг: http://52.77.99.18:8081
   - Зориулалт: Хэрэглэгчийн нэвтрэлт, бүртгэл болон токен үүсгэх

2. **User Details Service** - `/api/user-details/**` замаар дамжуулагдана
   - Хандах хаяг: http://localhost:8083
   - Зориулалт: Хэрэглэгчийн дэлгэрэнгүй мэдээллийг удирдах

### Шинэ үйлчилгээг холбох

API Gateway-д шинэ үйлчилгээ нэмэхийн тулд дараах алхмуудыг гүйцэтгэнэ:

1. `RouteConfig.java` файл дотор шинэ route нэмэх:

```java
.route("my-new-service", r -> r
    .path("/api/my-service/**")
    .filters(f -> f
        .stripPrefix(1)
        .filter(jwtAuthenticationFilter.apply(new JwtAuthenticationFilter.Config())))
    .uri("http://your-service-host:port"))
```

2. Үйлчилгээний нэр, зам болон хаягийг тохируулах
   - `my-new-service` - Үйлчилгээний дотоод нэр
   - `/api/my-service/**` - API Gateway дээр ил харагдах зам
   - `http://your-service-host:port` - Service-н хаяг

3. Filter-үүдийг тохируулах

### Бусад үйлчилгээнүүд API Gateway-тэй ажиллах зааварчилгаа

API Gateway ашигладаг бүх үйлчилгээнүүд нь API Gateway-с ирсэн header-үүдийг (X-User-ID, X-User-Roles) боловсруулах шаардлагатай. Энэ нь хэрэглэгчийн эрх, зөвшөөрлийг зөв шалгахад тусална.

#### 1. Authentication Filter үүсгэх

Доорх кодыг ашиглан GatewayHeadersAuthenticationFilter класс үүсгэнэ. Энэ фильтр нь API Gateway-с дамжуулагдсан хэрэглэгчийн ID болон ролийн мэдээллийг өөрийн үйлчилгээний SecurityContext-д хадгалж, бүх хүсэлтүүдэд хэрэглэгчийн нэвтрэлтийг баталгаажуулна.

```java
package com.example.өөрийн_сервисийн_нэр.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * API Gateway-с дамжуулагдсан хэрэглэгчийн ID болон эрхийн мэдээллийг
 * Spring Security-н SecurityContext руу шилжүүлэх фильтр.
 */
@Slf4j
public class GatewayHeadersAuthenticationFilter extends OncePerRequestFilter {

    private static final String USER_ID_HEADER = "X-User-ID";
    private static final String USER_ROLES_HEADER = "X-User-Roles";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        log.info("==== DEBUG: Request to {} ====", request.getRequestURI());
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            log.info("Header: {} = {}", headerName, request.getHeader(headerName));
        }
        log.info("==== END DEBUG ====");

        
        String userId = request.getHeader(USER_ID_HEADER);
        String rolesHeader = request.getHeader(USER_ROLES_HEADER);

        log.info("X-User-ID: {}, X-User-Roles: {}", userId, rolesHeader);

        
        if (userId != null && !userId.isEmpty() && rolesHeader != null && !rolesHeader.isEmpty()) {
            log.info("Gateway-с ирсэн header: ID={}, Roles={}", userId, rolesHeader);

            List<GrantedAuthority> authorities = new ArrayList<>();
            String[] roles = rolesHeader.split(",");
            for (String role : roles) {
                if (!role.trim().isEmpty()) {
                    String authority = role.trim();
                    log.info("Нэмж буй эрх: {}", authority);
                    authorities.add(new SimpleGrantedAuthority(authority));
                }
            }

            if (!authorities.isEmpty()) {
            
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId,
                        null,
                        authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("SecurityContext-д Authentication хийлээ: {}", authentication);
            } else {
                log.warn("Gateway-с ирсэн ролууд хоосон байна: {}", rolesHeader);
                SecurityContextHolder.clearContext();
            }
        } else {
            log.info("Gateway-н header-үүд олдсонгүй: userId={}, roles={}", userId, rolesHeader);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
```

#### 2. Security тохиргоог хийх

Security тохиргоонд дээр үүсгэсэн фильтрийг нэмж өгөх шаардлагатай. Үүний тулд SecurityConfig класст дараах тохиргоог хийнэ:
//-=-=
Энэ хоорондох торхиргоо чухал
//-=-=

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    //-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    GatewayHeadersAuthenticationFilter gatewayFilter = new GatewayHeadersAuthenticationFilter();
    //-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> 
            auth.requestMatchers("/user-details/**").permitAll()
            .anyRequest().authenticated()
        )
        //-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
        .addFilterBefore(gatewayFilter, AuthorizationFilter.class);
        //-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    return http.build();
}
```

#### 3. Фильтрийн ажиллах зарчим

1. API Gateway нь хэрэглэгчийн JWT токеныг шалгаж баталгаажуулна
2. Хүчинтэй токен байх үед Gateway нь үйлчилгээнд хүсэлт дамжуулахдаа `X-User-ID` болон `X-User-Roles` header-ийг нэмнэ
3. Үйлчилгээний `GatewayHeadersAuthenticationFilter` нь эдгээр header-ийг шалгаж, Spring Security-н SecurityContext-д хэрэглэгчийн мэдээллийг хадгална
4. Ингэснээр үйлчилгээн дотор `@PreAuthorize` зэрэг аннотацуудыг ашиглан эрх шалгах боломжтой болно

### API Gateway-г дуудах

Үйлчилгээнүүд API Gateway-г дуудахдаа:

1. API Gateway хаяг руу хүсэлт илгээнэ: `http://api-gateway-host:port/api/{service-path}`
2. Хүсэлтийн header-т JWT токеныг оруулна: `Authorization: Bearer {your_jwt_token}`

### Жишээ хүсэлт

```
POST http://api-gateway-host:port/api/auth/login
Content-Type: application/json

{
  "username": "хэрэглэгч",
  "password": "нууц_үг"
}
```

### Алдааны кодууд

- 401 - Хэрэглэгч нэвтрээгүй эсвэл токен хүчингүй
- 403 - Хэрэглэгч энэ үйлдлийг хийх эрхгүй
- 404 - Хүсэлт илгээсэн зам олдсонгүй
- 500 - Серверийн дотоод алдаа

### Нэмэлт
 - Хэрвээ user хэсэг ашиглах бол үүнийг татан user_detail_register service-г ажилуулах https://github.com/num-hospital-system/num_auth.git
 - ### Мөн gateway ашигласан бодит жишээ user_detail_register service дотор байгаа шүү GL
