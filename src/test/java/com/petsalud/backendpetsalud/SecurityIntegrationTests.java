package com.petsalud.backendpetsalud;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.petsalud.backendpetsalud.entity.Mascota;
import com.petsalud.backendpetsalud.entity.Producto;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.CitaRepository;
import com.petsalud.backendpetsalud.repository.ExpedienteMedicoRepository;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.NotificacionRepository;
import com.petsalud.backendpetsalud.repository.ProductoRepository;
import com.petsalud.backendpetsalud.repository.RecompensaRepository;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import com.petsalud.backendpetsalud.repository.VentaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private MascotaRepository mascotaRepository;

    @Autowired
    private ProductoRepository productoRepository;

    @Autowired
    private CitaRepository citaRepository;

    @Autowired
    private ExpedienteMedicoRepository expedienteMedicoRepository;

    @Autowired
    private VentaRepository ventaRepository;

    @Autowired
    private RecompensaRepository recompensaRepository;

    @Autowired
    private NotificacionRepository notificacionRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private Usuario cliente;
    private Usuario otroCliente;
    private Usuario empleado;
    private Usuario veterinario;
    private Usuario gerente;
    private Mascota mascotaCliente;
    private Producto productoInicial;

    @BeforeEach
    void setUp() {
        ventaRepository.deleteAll();
        recompensaRepository.deleteAll();
        notificacionRepository.deleteAll();
        expedienteMedicoRepository.deleteAll();
        citaRepository.deleteAll();
        mascotaRepository.deleteAll();
        productoRepository.deleteAll();
        usuarioRepository.deleteAll();

        cliente = crearUsuario("cliente.test@petsalud.cl", "ClaveSegura1!", "Ana", Rol.CLIENTE);
        otroCliente = crearUsuario("otro.cliente@petsalud.cl", "ClaveSegura2!", "Pedro", Rol.CLIENTE);
        empleado = crearUsuario("empleado.test@petsalud.cl", "ClaveSegura3!", "Luis", Rol.EMPLEADO);
        veterinario = crearUsuario("vet.test@petsalud.cl", "ClaveSegura4!", "Dra. Sofia", Rol.VETERINARIO);
        gerente = crearUsuario("gerente.test@petsalud.cl", "ClaveSegura5!", "Carlos", Rol.GERENTE);

        mascotaCliente = mascotaRepository.save(Mascota.builder()
                .nombre("Luna")
                .especie("Felino")
                .raza("Siames")
                .fechaNacimiento(LocalDate.of(2023, 3, 10))
                .sexo("Hembra")
                .propietario(cliente)
                .build());

        productoInicial = productoRepository.save(Producto.builder()
                .nombre("Alimento Gato Premium 10kg")
                .descripcion("Alimento hipoalergenico")
                .precio(new BigDecimal("38990"))
                .stock(3)
                .categoria("Alimentos")
                .build());
    }

    private Usuario crearUsuario(String email, String rawPassword, String nombre, Rol rol) {
        return usuarioRepository.save(Usuario.builder()
                .email(email)
                .password(passwordEncoder.encode(rawPassword))
                .nombre(nombre)
                .apellido("PetSalud")
                .telefono("+56999999999")
                .direccion("Santiago")
                .rol(rol)
                .build());
    }

    private String obtenerToken(String email, String password) throws Exception {
        String payload = objectMapper.writeValueAsString(Map.of("email", email, "password", password));
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        return json.get("token").asText();
    }

    @Test
    @DisplayName("1. Registro cifra contrasena con BCrypt, oculta password en JSON y previene escalacion de privilegios")
    void registroCifraPasswordConBCryptYOcultaEnRespuesta() throws Exception {
        String body = """
                {
                  "email": "nuevo@petsalud.cl",
                  "password": "MiPassword2026!",
                  "nombre": "Matias",
                  "apellido": "Silva",
                  "rol": "ADMIN"
                }
                """;

        MvcResult result = mockMvc.perform(post("/api/auth/registro")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("nuevo@petsalud.cl"))
                .andExpect(jsonPath("$.rol").value("CLIENTE"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).doesNotContain("MiPassword2026!");

        Usuario guardado = usuarioRepository.findByEmail("nuevo@petsalud.cl").orElseThrow();
        assertThat(guardado.getPassword()).startsWith("$2a$");
        assertThat(passwordEncoder.matches("MiPassword2026!", guardado.getPassword())).isTrue();
    }

    @Test
    @DisplayName("2. Rechaza acceso sin token o con token JWT adulterado con 401 Unauthorized y cabeceras seguras")
    void rechazaAccesoSinTokenOConTokenInvalido() throws Exception {
        mockMvc.perform(get("/api/productos"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("Content-Security-Policy"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));

        mockMvc.perform(get("/api/productos")
                        .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.token.adulterado"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("3. Rol CLIENTE accede a sus recursos pero recibe 403 en operaciones administrativas, clinicas o ajenas (IDOR)")
    void permisosRolCliente() throws Exception {
        String tokenCliente = obtenerToken("cliente.test@petsalud.cl", "ClaveSegura1!");

        // Permitidos para CLIENTE
        mockMvc.perform(get("/api/productos")
                        .header("Authorization", "Bearer " + tokenCliente))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/usuarios/" + cliente.getId())
                        .header("Authorization", "Bearer " + tokenCliente))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("cliente.test@petsalud.cl"));

        mockMvc.perform(post("/api/ventas")
                        .param("usuarioId", cliente.getId().toString())
                        .header("Authorization", "Bearer " + tokenCliente)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(List.of(productoInicial.getId()))))
                .andExpect(status().isOk());

        // Prohibidos para CLIENTE (403 Forbidden)
        // IDOR: intentar ver datos personales de otro cliente
        mockMvc.perform(get("/api/usuarios/" + otroCliente.getId())
                        .header("Authorization", "Bearer " + tokenCliente))
                .andExpect(status().isForbidden());

        // Listar todos los usuarios
        mockMvc.perform(get("/api/usuarios")
                        .header("Authorization", "Bearer " + tokenCliente))
                .andExpect(status().isForbidden());

        // Agregar producto al inventario
        mockMvc.perform(post("/api/productos")
                        .header("Authorization", "Bearer " + tokenCliente)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\":\"Nuevo\",\"precio\":1000,\"stock\":10,\"categoria\":\"Accesorios\"}"))
                .andExpect(status().isForbidden());

        // Crear expediente medico
        mockMvc.perform(post("/api/expedientes")
                        .param("mascotaId", mascotaCliente.getId().toString())
                        .param("veterinarioId", veterinario.getId().toString())
                        .header("Authorization", "Bearer " + tokenCliente)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"descripcion\":\"Consulta\",\"diagnostico\":\"Sano\",\"tratamiento\":\"Ninguno\"}"))
                .andExpect(status().isForbidden());

        // Consultar todas las ventas
        mockMvc.perform(get("/api/ventas")
                        .header("Authorization", "Bearer " + tokenCliente))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("4. Roles EMPLEADO y VETERINARIO ejecutan operaciones operativas/clinicas pero reciben 403 en funciones exclusivas de GERENTE")
    void permisosRolEmpleadoYVeterinario() throws Exception {
        String tokenEmpleado = obtenerToken("empleado.test@petsalud.cl", "ClaveSegura3!");
        String tokenVeterinario = obtenerToken("vet.test@petsalud.cl", "ClaveSegura4!");

        // EMPLEADO puede consultar stock bajo y actualizar stock
        mockMvc.perform(get("/api/productos/stock-bajo")
                        .param("cantidad", "5")
                        .header("Authorization", "Bearer " + tokenEmpleado))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].nombre").value("Alimento Gato Premium 10kg"));

        Producto actualizado = Producto.builder()
                .nombre("Alimento Gato Premium 10kg")
                .descripcion("Alimento hipoalergenico")
                .precio(new BigDecimal("38990"))
                .stock(20)
                .categoria("Alimentos")
                .build();

        mockMvc.perform(put("/api/productos/" + productoInicial.getId())
                        .header("Authorization", "Bearer " + tokenEmpleado)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(actualizado)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.stock").value(20));

        // EMPLEADO NO puede eliminar productos ni usuarios
        mockMvc.perform(delete("/api/productos/" + productoInicial.getId())
                        .header("Authorization", "Bearer " + tokenEmpleado))
                .andExpect(status().isForbidden());

        mockMvc.perform(delete("/api/usuarios/" + otroCliente.getId())
                        .header("Authorization", "Bearer " + tokenEmpleado))
                .andExpect(status().isForbidden());

        // VETERINARIO puede registrar expediente medico
        MvcResult expResult = mockMvc.perform(post("/api/expedientes")
                        .param("mascotaId", mascotaCliente.getId().toString())
                        .param("veterinarioId", veterinario.getId().toString())
                        .header("Authorization", "Bearer " + tokenVeterinario)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"descripcion\":\"Control anual\",\"diagnostico\":\"Saludable\",\"tratamiento\":\"Vacuna antirrabica\"}"))
                .andExpect(status().isOk())
                .andReturn();

        Long expedienteId = objectMapper.readTree(expResult.getResponse().getContentAsString()).get("id").asLong();

        // VETERINARIO NO puede eliminar un expediente medico (exclusivo GERENTE/ADMIN)
        mockMvc.perform(delete("/api/expedientes/" + expedienteId)
                        .header("Authorization", "Bearer " + tokenVeterinario))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("5. Rol GERENTE accede a gestion total de inventario, usuarios, reportes de ventas y bitacora de seguridad")
    void permisosRolGerente() throws Exception {
        String tokenGerente = obtenerToken("gerente.test@petsalud.cl", "ClaveSegura5!");

        // Agregar nuevo producto
        MvcResult prodResult = mockMvc.perform(post("/api/productos")
                        .header("Authorization", "Bearer " + tokenGerente)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\":\"Juguete Interactivo\",\"descripcion\":\"Cuerda dental\",\"precio\":8990,\"stock\":50,\"categoria\":\"Juguetes\"}"))
                .andExpect(status().isOk())
                .andReturn();

        Long nuevoProdId = objectMapper.readTree(prodResult.getResponse().getContentAsString()).get("id").asLong();

        // Listar todos los usuarios
        mockMvc.perform(get("/api/usuarios")
                        .header("Authorization", "Bearer " + tokenGerente))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(5));

        // Listar todas las ventas consolidadas
        mockMvc.perform(get("/api/ventas")
                        .header("Authorization", "Bearer " + tokenGerente))
                .andExpect(status().isOk());

        // Consultar bitacora de eventos de seguridad
        mockMvc.perform(get("/api/seguridad/eventos")
                        .header("Authorization", "Bearer " + tokenGerente))
                .andExpect(status().isOk());

        // Eliminar producto
        mockMvc.perform(delete("/api/productos/" + nuevoProdId)
                        .header("Authorization", "Bearer " + tokenGerente))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("6. Monitoreo detecta multiples intentos fallidos de login y bloquea cuenta por fuerza bruta (429)")
    void bloqueoTemporalPorFuerzaBruta() throws Exception {
        String badPayload = objectMapper.writeValueAsString(Map.of(
                "email", "BruteForceTarget@petsalud.cl",
                "password", "Incorrecta123"
        ));

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(badPayload))
                    .andExpect(status().isUnauthorized());
        }

        // Al 6to intento la cuenta se encuentra temporalmente bloqueada (429 Too Many Requests)
        mockMvc.perform(post("/api/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(badPayload))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("Cuenta Temporalmente Bloqueada"));
    }
}
