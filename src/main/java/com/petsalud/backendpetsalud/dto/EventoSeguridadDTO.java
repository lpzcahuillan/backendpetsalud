package com.petsalud.backendpetsalud.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EventoSeguridadDTO {
    private LocalDateTime fechaHora;
    private String tipoEvento;
    private String usuario;
    private String direccionIp;
    private String recurso;
    private String detalle;
}
