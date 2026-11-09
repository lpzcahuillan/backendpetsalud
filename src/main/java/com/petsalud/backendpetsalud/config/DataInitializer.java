package com.petsalud.backendpetsalud.config;

import com.petsalud.backendpetsalud.entity.Mascota;
import com.petsalud.backendpetsalud.entity.Producto;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.MascotaRepository;
import com.petsalud.backendpetsalud.repository.ProductoRepository;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * Inicializador opcional de datos semilla para facilitar pruebas funcionales
 * de cada rol (CLIENTE, EMPLEADO, VETERINARIO, GERENTE, ADMIN) en Clinica PetSalud.
 */
@Configuration
public class DataInitializer {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    @ConditionalOnProperty(name = "petsalud.seed.enabled", havingValue = "true")
    public CommandLineRunner initSecuritySeedData(
            UsuarioRepository usuarioRepository,
            MascotaRepository mascotaRepository,
            ProductoRepository productoRepository,
            PasswordEncoder passwordEncoder) {

        return args -> {
            Usuario cliente = crearUsuarioSiNoExiste(usuarioRepository, passwordEncoder,
                    "cliente@petsalud.cl", "Cliente123!", "Camila", "Munoz", "+56911111111", "Providencia 1234, Santiago", Rol.CLIENTE);

            crearUsuarioSiNoExiste(usuarioRepository, passwordEncoder,
                    "empleado@petsalud.cl", "Empleado123!", "Diego", "Soto", "+56922222222", "Av. Libertad 450, Vina del Mar", Rol.EMPLEADO);

            crearUsuarioSiNoExiste(usuarioRepository, passwordEncoder,
                    "veterinario@petsalud.cl", "Vet123456!", "Dra. Valentina", "Rojas", "+56933333333", "Las Condes 890, Santiago", Rol.VETERINARIO);

            crearUsuarioSiNoExiste(usuarioRepository, passwordEncoder,
                    "gerente@petsalud.cl", "Gerente123!", "Roberto", "Contreras", "+56944444444", "Casa Matriz, Santiago", Rol.GERENTE);

            crearUsuarioSiNoExiste(usuarioRepository, passwordEncoder,
                    "admin@petsalud.cl", "Admin12345!", "Administrador", "PetSalud", "+56955555555", "TI Central, Santiago", Rol.ADMIN);

            if (mascotaRepository.count() == 0 && cliente != null) {
                mascotaRepository.save(Mascota.builder()
                        .nombre("Copito")
                        .especie("Canino")
                        .raza("Poodle")
                        .fechaNacimiento(LocalDate.of(2022, 5, 14))
                        .sexo("Macho")
                        .propietario(cliente)
                        .build());
            }

            if (productoRepository.count() == 0) {
                productoRepository.save(Producto.builder()
                        .nombre("Alimento Premium Adulto 15kg")
                        .descripcion("Alimento balanceado para perros adultos")
                        .precio(new BigDecimal("45990"))
                        .stock(25)
                        .categoria("Alimentos")
                        .build());

                productoRepository.save(Producto.builder()
                        .nombre("Collar Antiparasitario")
                        .descripcion("Proteccion continua por 8 meses")
                        .precio(new BigDecimal("22990"))
                        .stock(4)
                        .categoria("Accesorios")
                        .build());
            }

            logger.info("Datos iniciales de seguridad cargados para Clinica PetSalud (CLIENTE, EMPLEADO, VETERINARIO, GERENTE, ADMIN).");
        };
    }

    private Usuario crearUsuarioSiNoExiste(
            UsuarioRepository repo,
            PasswordEncoder encoder,
            String email,
            String rawPassword,
            String nombre,
            String apellido,
            String telefono,
            String direccion,
            Rol rol) {

        return repo.findByEmail(email).orElseGet(() -> repo.save(
                Usuario.builder()
                        .email(email)
                        .password(encoder.encode(rawPassword))
                        .nombre(nombre)
                        .apellido(apellido)
                        .telefono(telefono)
                        .direccion(direccion)
                        .rol(rol)
                        .build()
        ));
    }
}
