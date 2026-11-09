package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.dto.EventoSeguridadDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Servicio de monitoreo basico de actividades sospechosas, auditoria de accesos
 * y proteccion contra ataques de fuerza bruta en el inicio de sesion.
 */
@Service
public class SecurityAuditService {

    private static final Logger auditLogger = LoggerFactory.getLogger("AUDITORIA_SEGURIDAD");
    private static final int MAX_EVENTOS_MEMORIA = 200;

    @Value("${security.login.max-attempts:5}")
    private int maxIntentosFallidos;

    @Value("${security.login.lock-time-minutes:15}")
    private int minutosBloqueo;

    private final Map<String, RegistroIntentos> intentosPorClave = new ConcurrentHashMap<>();
    private final Deque<EventoSeguridadDTO> bitacoraEventos = new ConcurrentLinkedDeque<>();

    public void registrarEvento(String tipoEvento, String usuario, String ip, String recurso, String detalle) {
        EventoSeguridadDTO evento = EventoSeguridadDTO.builder()
                .fechaHora(LocalDateTime.now())
                .tipoEvento(tipoEvento)
                .usuario(usuario != null ? usuario : "ANONIMO")
                .direccionIp(ip != null ? ip : "DESCONOCIDA")
                .recurso(recurso)
                .detalle(detalle)
                .build();

        bitacoraEventos.addFirst(evento);
        while (bitacoraEventos.size() > MAX_EVENTOS_MEMORIA) {
            bitacoraEventos.removeLast();
        }

        if (tipoEvento.contains("ALERTA") || tipoEvento.contains("DENEGADO") || tipoEvento.contains("INVALIDO") || tipoEvento.contains("FALLIDO")) {
            auditLogger.warn("[{}] Usuario={} | IP={} | Recurso={} | Detalle={}",
                    tipoEvento, evento.getUsuario(), evento.getDireccionIp(), recurso, detalle);
        } else {
            auditLogger.info("[{}] Usuario={} | IP={} | Recurso={} | Detalle={}",
                    tipoEvento, evento.getUsuario(), evento.getDireccionIp(), recurso, detalle);
        }
    }

    public boolean estaBloqueado(String email) {
        if (email == null) {
            return false;
        }
        String clave = email.toLowerCase();
        RegistroIntentos registro = intentosPorClave.get(clave);
        if (registro == null || registro.bloqueadoHasta == null) {
            return false;
        }
        if (LocalDateTime.now().isAfter(registro.bloqueadoHasta)) {
            intentosPorClave.remove(clave);
            return false;
        }
        return true;
    }

    public void registrarIntentoFallido(String email, String ip) {
        if (email == null) {
            return;
        }
        String clave = email.toLowerCase();
        RegistroIntentos registro = intentosPorClave.compute(clave, (k, actual) -> {
            if (actual == null) {
                return new RegistroIntentos(1, null);
            }
            int nuevosIntentos = actual.intentos + 1;
            LocalDateTime bloqueo = actual.bloqueadoHasta;
            if (nuevosIntentos >= maxIntentosFallidos) {
                bloqueo = LocalDateTime.now().plusMinutes(minutosBloqueo);
            }
            return new RegistroIntentos(nuevosIntentos, bloqueo);
        });

        registrarEvento("LOGIN_FALLIDO", email, ip, "/api/auth/login",
                "Credenciales invalidas (intento " + registro.intentos + " de " + maxIntentosFallidos + ")");

        if (registro.intentos >= maxIntentosFallidos) {
            registrarEvento("ALERTA_FUERZA_BRUTA", email, ip, "/api/auth/login",
                    "Cuenta bloqueada temporalmente por " + minutosBloqueo + " minutos tras " + registro.intentos + " intentos fallidos");
        }
    }

    public void limpiarIntentosFallidos(String email, String ip) {
        if (email != null) {
            intentosPorClave.remove(email.toLowerCase());
        }
        registrarEvento("LOGIN_EXITOSO", email, ip, "/api/auth/login", "Inicio de sesion autenticado con JWT");
    }

    public List<EventoSeguridadDTO> obtenerEventosRecientes() {
        return Collections.unmodifiableList(new ArrayList<>(bitacoraEventos));
    }

    private record RegistroIntentos(int intentos, LocalDateTime bloqueadoHasta) {
    }
}
