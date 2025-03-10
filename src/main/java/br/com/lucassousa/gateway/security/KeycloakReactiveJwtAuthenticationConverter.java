package br.com.lucassousa.gateway.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;

public class KeycloakReactiveJwtAuthenticationConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

    private final List<String> clientIds;

    public KeycloakReactiveJwtAuthenticationConverter(List<String> clientIds) {
        this.clientIds = clientIds;
    }

    @Override
    public Flux<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> roles = extractResourceRoles(jwt);
        System.out.println(roles);
        return Flux.fromIterable(extractResourceRoles(jwt));
    }

    private Collection<GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Object resourceAccessClaim = jwt.getClaim("resource_access");

        if (!(resourceAccessClaim instanceof Map<?, ?> resourceAccess)) {
            return Collections.emptySet();
        }

        return clientIds.stream()
                .map(clientId -> extractRolesForClient(resourceAccess, clientId))
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
    }

    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> extractRolesForClient(Map<?, ?> resourceAccess, String clientId) {
        Object clientRolesObj = resourceAccess.get(clientId);

        if (!(clientRolesObj instanceof Map<?, ?> clientRolesMap)) {
            return Collections.emptySet();
        }

        Object rolesObj = clientRolesMap.get("roles");

        if (!(rolesObj instanceof List<?> rolesList)) {
            return Collections.emptySet();
        }

        return rolesList.stream()
                .filter(role -> role instanceof String)
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}
