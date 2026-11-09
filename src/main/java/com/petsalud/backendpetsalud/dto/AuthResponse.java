package com.petsalud.backendpetsalud.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String token;
    private String tipoToken;
    private Long usuarioId;
    private String email;
    private String nombre;
    private String rol;
    private long expiraEnMs;
}
