# Clínica PetSalud - Backend Seguro con Spring Security y JWT

Aplicación backend desarrollada con **Spring Boot 3.3.6** y **Spring Security 6** para **Clínica PetSalud** (Actividad Sumativa Semana 3 — *Desarrollo Backend II - PBY2202*, Duoc UC).

## Características de Seguridad Implementadas

- **Autenticación Sin Estado (Stateless) con JWT**: Generación y validación criptográfica de tokens firmados con `HMAC-SHA256` (`io.jsonwebtoken` / `JJWT 0.12.6`) mediante [`JwtUtil`](src/main/java/com/petsalud/backendpetsalud/security/JwtUtil.java) y el filtro interceptor [`JwtAuthenticationFilter`](src/main/java/com/petsalud/backendpetsalud/security/JwtAuthenticationFilter.java).
- **Protección de Credenciales con BCrypt**: Hash irreversible con sal aleatoria (`BCryptPasswordEncoder` factor 10) en el registro de usuarios y ocultamiento estricto del atributo `password` (`WRITE_ONLY`) en las respuestas JSON.
- **Autorización Basada en Roles (RBAC) y Defensa en Profundidad**:
  - Reglas declarativas por endpoint/método HTTP en [`SecurityConfig`](src/main/java/com/petsalud/backendpetsalud/security/SecurityConfig.java).
  - Control granular a nivel de método con `@PreAuthorize` y validación de propiedad de recursos (`@seguridadUsuario.esPropioUsuario(...)`) para prevenir accesos horizontales no autorizados (**IDOR**) en cumplimiento de la **Ley N° 19.628 / Ley N° 21.719** sobre Protección de Datos Personales en Chile.
- **Monitoreo de Actividades Sospechosas y Mitigación de Fuerza Bruta**:
  - [`SecurityAuditService`](src/main/java/com/petsalud/backendpetsalud/security/SecurityAuditService.java) registra intentos de inicio de sesión exitosos/fallidos, tokens inválidos o expirados y rechazos `401`/`403`, bloqueando temporalmente cuentas tras múltiples intentos fallidos consecutivos (`429 Too Many Requests`).
  - Endpoint administrativo `GET /api/seguridad/eventos` exclusivo para `GERENTE` y `ADMIN`.
- **Cabeceras HTTP de Seguridad y Mitigación OWASP**:
  - `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Strict-Transport-Security (HSTS)` y configuración explícita de `CORS`.

---

## Roles del Sistema

| Rol | Nivel de Acceso | Permisos Principales |
|---|---|---|
| `CLIENTE` | Externo / Propietario | Consultar catálogo de productos, gestionar su propio perfil y mascotas, agendar citas, consultar historial médico de su mascota, realizar compras propias y ver sus recompensas/notificaciones. |
| `EMPLEADO` | Operativo de Sucursal | Consultar alertas de stock bajo, actualizar stock/productos, registrar ventas en sucursal, gestionar citas, enviar notificaciones y asignar recompensas. |
| `VETERINARIO` | Clínico | Crear y consultar expedientes médicos (diagnósticos y tratamientos), gestionar agenda y actualizar estados de citas médicas. |
| `GERENTE` | Supervisión y Gestión | Acceso completo a gestión de inventario (alta/baja de productos), reportes consolidados de ventas, administración de usuarios y bitácora de monitoreo de seguridad. |
| `ADMIN` | Administración TI | Control total homologado con gerencia sobre todos los módulos y auditoría del sistema. |

---

## Requisitos y Ejecución

- **Java 17** o superior
- **Maven 3.9+**
- **MySQL 8+** (o ejecución inmediata en memoria usando el perfil `dev` con H2)

### Opción A: Ejecución rápida con H2 en memoria (sin requerir MySQL local)

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

### Opción B: Ejecución con MySQL

Configura las variables de entorno (o edita `src/main/resources/application.properties`):

```bash
export DB_URL="jdbc:mysql://localhost:3306/petsalud_db?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=America/Santiago"
export DB_USERNAME="root"
export DB_PASSWORD="tu_password"
./mvnw spring-boot:run
```

### Ejecución de Pruebas Automatizadas de Seguridad

```bash
./mvnw test
```

---

## Usuarios de Prueba Precargados (`petsalud.seed.enabled=true`)

| Rol | Email | Contraseña |
|---|---|---|
| `CLIENTE` | `cliente@petsalud.cl` | `Cliente123!` |
| `EMPLEADO` | `empleado@petsalud.cl` | `Empleado123!` |
| `VETERINARIO` | `veterinario@petsalud.cl` | `Vet123456!` |
| `GERENTE` | `gerente@petsalud.cl` | `Gerente123!` |
| `ADMIN` | `admin@petsalud.cl` | `Admin12345!` |

---

## Ejemplos de Prueba (Postman / cURL)

### 1. Iniciar sesión y obtener token JWT

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"gerente@petsalud.cl","password":"Gerente123!"}'
```

### 2. Consumir un endpoint protegido enviando el JWT

```bash
curl -X GET http://localhost:8080/api/usuarios \
  -H "Authorization: Bearer <TU_TOKEN_JWT>"
```

### 3. Consultar bitácora de monitoreo de seguridad (`GERENTE` / `ADMIN`)

```bash
curl -X GET http://localhost:8080/api/seguridad/eventos \
  -H "Authorization: Bearer <TOKEN_GERENTE>"
```
