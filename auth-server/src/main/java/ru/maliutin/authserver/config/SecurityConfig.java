package ru.maliutin.authserver.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

import javax.sql.DataSource;
import java.util.UUID;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.*;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;

/**
 * Конфигурация сервера авторизации
 */
@Configuration
public class SecurityConfig {

    /**
     * Создание менеджера сведений о пользователя.
     * @param dataSource объект БД.
     * @return менеджер пользователей.
     */
    @Bean
    public JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }

    /**
     * Репозиторий для хранения зарегистрированных клиентов.
     * @param jdbcTemplate объект подключения к БД.
     * @return репозиторий.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate){
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * Задание первоначальных настроек сервера аутентификации.
     * Создание клиента и пользователя в случае их отсутствия.
     * Данные клиента по умолчанию:
     * clientId - client
     * clientSecret - secret
     * Данные пользователя по умолчанию:
     * логин - user
     * пароль - password
     * @param registeredClientRepository объект регистрации клиентов.
     * @param userDetailsManager объект менеджера пользователей.
     * @return настройки по умолчанию.
     */
    @Bean
    ApplicationRunner clientRunner(RegisteredClientRepository registeredClientRepository, UserDetailsManager userDetailsManager){
        return args -> {
            // Создание клиента
            var clientId = "client";
          if (registeredClientRepository.findByClientId(clientId) == null){
              registeredClientRepository.save(RegisteredClient
                      .withId(UUID.randomUUID().toString())
                      .clientId(clientId)
                      .clientSecret("$2a$12$Gx9MVqU0oy9qpgU.v58ZueJ1G9K8BCJay2lzQnKe.v.URlCF3vMjG")
                      .authorizationGrantType(AUTHORIZATION_CODE)
                      .authorizationGrantType(CLIENT_CREDENTIALS)
                      .authorizationGrantType(REFRESH_TOKEN)
                      .redirectUris(uris -> uris.add("http://127.0.0.1:8080/login/oauth2/code/reg-client"))
                      .scope("user.read")
                      .scope("user.write")
                      .scope("openid")
                      .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
                      .clientSettings(ClientSettings
                              .builder()
                              .requireAuthorizationConsent(true)
                              .build()
                      )
                      .build()
              );
          }
          // Создание пользователя
          if(!userDetailsManager.userExists("user")){
              var userBuilder = User.builder();
              UserDetails user = userBuilder
                .username("user")
                .password("$2a$12$ykMB/XiGd74cg1MTy3.FdOzcysss5pPpLmc3Zp4YVJtZMYVidC52K")
                .roles("USER", "ADMIN").build();
              userDetailsManager.createUser(user);
          }
        };
    }

    /**
     * Шифрование паролей при помощи Bcrypt.
     * @return объект PasswordEncoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(12);
    }
}
