package com.petsalud.backendpetsalud.entity;

/**
 * Roles de seguridad del sistema Clinica PetSalud.
 * - CLIENTE: Dueno de mascota con acceso a sus citas, mascotas, compras y notificaciones.
 * - EMPLEADO: Personal operativo de sucursal (ventas, recepcion, stock operativo, citas).
 * - VETERINARIO: Profesional clinico con acceso a expedientes medicos y atencion de citas.
 * - GERENTE: Supervision de sucursales, reportes globales de ventas, inventario y usuarios.
 * - ADMIN: Administrador general del sistema con control total y auditoria de seguridad.
 */
public enum Rol {
    CLIENTE,
    EMPLEADO,
    VETERINARIO,
    GERENTE,
    ADMIN
}
