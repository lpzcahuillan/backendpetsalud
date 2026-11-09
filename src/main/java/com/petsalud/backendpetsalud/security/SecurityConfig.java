package com.petsalud.backendpetsalud.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Configuracion central de Spring Security para Clinica PetSalud.
 * Implementa arquitectura sin estado (Stateless) con JWT, cifrado BCrypt,
 * cabeceras de proteccion HTTP (XSS, Clickjacking, HSTS) y control de acceso RBAC.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private UsuarioDetailsService usuarioDetailsService;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Configuracion explicita de CORS para interoperabilidad segura con frontends autorizados
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // API REST Stateless basada en Authorization: Bearer <JWT> (sin cookies de sesion)
                .csrf(AbstractHttpConfigurer::disable)
                // Cabeceras de seguridad frente a XSS, MIME sniffing, Clickjacking y degradacion HTTPS
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; frame-ancestors 'self'; form-action 'self'"))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                        .contentTypeOptions(Customizer.withDefaults())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000))
                )
                // Politica sin estado: el servidor no almacena HttpSession
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Respuestas JSON controladas para errores 401 y 403
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                // Reglas de autorizacion por URL y metodo HTTP (Defensa en Profundidad junto a @PreAuthorize)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/api/login", "/api/usuarios/registro", "/h2-console/**").permitAll()
                        .requestMatchers("/api/seguridad/**", "/api/admin/**").hasAnyRole("GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/usuarios").hasAnyRole("GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/usuarios/**").hasAnyRole("GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/productos").hasAnyRole("GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/productos/**").hasAnyRole("EMPLEADO", "GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/productos/**").hasAnyRole("GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/productos/stock-bajo").hasAnyRole("EMPLEADO", "GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/expedientes/**").hasAnyRole("EMPLEADO", "VETERINARIO", "GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/expedientes/**").hasAnyRole("GERENTE", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/ventas").hasAnyRole("GERENTE", "ADMIN")
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(usuarioDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of("http://localhost:*", "https://*.petsalud.cl"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
        configuration.setExposedHeaders(List.of("Authorization"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
