package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.dto.AuthResponse;
import com.petsalud.backendpetsalud.dto.LoginRequest;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.SecurityAuditService;
import com.petsalud.backendpetsalud.security.UsuarioDetails;
import com.petsalud.backendpetsalud.service.UsuarioService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Controlador de autenticacion sin estado (JWT) para Clinica PetSalud.
 * Soporta tanto /api/auth/login como /api/login para compatibilidad completa.
 */
@RestController
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UsuarioService usuarioService;

    @Autowired
    private SecurityAuditService securityAuditService;

    @PostMapping({"/api/auth/login", "/api/login"})
    public ResponseEntity<?> iniciarSesion(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        if (loginRequest.getEmail() == null || loginRequest.getPassword() == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "status", 400,
                    "error", "Solicitud Invalida",
                    "message", "Debe proporcionar email y password"
            ));
        }

        if (securityAuditService.estaBloqueado(loginRequest.getEmail())) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("timestamp", LocalDateTime.now().toString());
            body.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
            body.put("error", "Cuenta Temporalmente Bloqueada");
            body.put("message", "Se detectaron multiples intentos fallidos. Intente nuevamente mas tarde.");
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(body);
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            UsuarioDetails userDetails = (UsuarioDetails) authentication.getPrincipal();
            String token = jwtUtil.generateToken(userDetails);
            securityAuditService.limpiarIntentosFallidos(loginRequest.getEmail(), request.getRemoteAddr());

            AuthResponse authResponse = AuthResponse.builder()
                    .token(token)
                    .tipoToken("Bearer")
                    .usuarioId(userDetails.getId())
                    .email(userDetails.getUsername())
                    .nombre(userDetails.getUsuario().getNombre())
                    .rol(userDetails.getRol().name())
                    .expiraEnMs(jwtUtil.getExpirationMs())
                    .build();

            return ResponseEntity.ok(authResponse);
        } catch (AuthenticationException ex) {
            securityAuditService.registrarIntentoFallido(loginRequest.getEmail(), request.getRemoteAddr());
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("timestamp", LocalDateTime.now().toString());
            body.put("status", HttpStatus.UNAUTHORIZED.value());
            body.put("error", "No Autorizado");
            body.put("message", "Credenciales de acceso incorrectas");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
        }
    }

    /**
     * Endpoint de autorregistro publico exclusivo para clientes (asigna Rol.CLIENTE forzosamente
     * previniendo ataques de escalacion de privilegios / Mass Assignment).
     */
    @PostMapping("/api/auth/registro")
    public ResponseEntity<Usuario> registrarCliente(@RequestBody Usuario usuario, HttpServletRequest request) {
        usuario.setRol(Rol.CLIENTE);
        Usuario nuevoUsuario = usuarioService.registrarUsuario(usuario);
        securityAuditService.registrarEvento(
                "REGISTRO_CLIENTE",
                nuevoUsuario.getEmail(),
                request.getRemoteAddr(),
                request.getRequestURI(),
                "Nuevo cliente registrado con contrasena cifrada BCrypt"
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(nuevoUsuario);
    }
}
