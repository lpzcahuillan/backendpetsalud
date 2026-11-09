package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filtro HTTP sin estado (Stateless) que intercepta cada peticion para validar
 * el token JWT enviado en el encabezado Authorization: Bearer <token>.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UsuarioDetailsService usuarioDetailsService;

    @Autowired
    private SecurityAuditService securityAuditService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        try {
            final String userEmail = jwtUtil.extractUsername(jwt);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = usuarioDetailsService.loadUserByUsername(userEmail);

                if (jwtUtil.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (ExpiredJwtException ex) {
            securityAuditService.registrarEvento(
                    "TOKEN_EXPIRADO",
                    ex.getClaims() != null ? ex.getClaims().getSubject() : "DESCONOCIDO",
                    request.getRemoteAddr(),
                    request.getRequestURI(),
                    "Token JWT expirado"
            );
        } catch (JwtException | IllegalArgumentException | UsernameNotFoundException ex) {
            securityAuditService.registrarEvento(
                    "TOKEN_INVALIDO",
                    "DESCONOCIDO",
                    request.getRemoteAddr(),
                    request.getRequestURI(),
                    "Token JWT invalido o manipulado: " + ex.getMessage()
            );
        }

        filterChain.doFilter(request, response);
    }
}
