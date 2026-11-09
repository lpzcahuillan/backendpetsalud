package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.dto.EventoSeguridadDTO;
import com.petsalud.backendpetsalud.security.SecurityAuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Controlador de monitoreo de seguridad y auditoria de actividades sospechosas.
 * Restringido exclusivamente a roles GERENTE y ADMIN.
 */
@RestController
@RequestMapping("/api/seguridad")
public class SeguridadController {

    @Autowired
    private SecurityAuditService securityAuditService;

    @GetMapping("/eventos")
    @PreAuthorize("hasAnyRole('GERENTE', 'ADMIN')")
    public ResponseEntity<List<EventoSeguridadDTO>> obtenerEventosSeguridad() {
        return ResponseEntity.ok(securityAuditService.obtenerEventosRecientes());
    }
}
