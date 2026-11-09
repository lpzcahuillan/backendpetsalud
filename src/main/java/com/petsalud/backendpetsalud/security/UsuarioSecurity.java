package com.petsalud.backendpetsalud.security;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Componente auxiliar de autorizacion a nivel de objeto (prevencion de IDOR)
 * para garantizar que un CLIENTE solo acceda a sus propios datos personales.
 */
@Component("seguridadUsuario")
public class UsuarioSecurity {

    public boolean esPropioUsuario(Authentication authentication, Long usuarioId) {
        if (authentication == null || !authentication.isAuthenticated() || usuarioId == null) {
            return false;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UsuarioDetails usuarioDetails) {
            return usuarioId.equals(usuarioDetails.getId());
        }
        return false;
    }
}
