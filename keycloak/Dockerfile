FROM quay.io/keycloak/keycloak:18.0.0  as builder
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_FEATURES=token-exchange,impersonation,scripts
ENV KC_DB=postgres
ENV KC_HTTP_ENABLED=true
ENV KC_HTTP_RELATIVE_PATH=/auth
# Install custom providers
RUN curl -sL https://github.com/aerogear/keycloak-metrics-spi/releases/download/2.5.3/keycloak-metrics-spi-2.5.3.jar -o /opt/keycloak/providers/keycloak-metrics-spi-2.5.3.jar
#RUN /opt/keycloak/bin/kc.sh build --db=postgres
RUN /opt/keycloak/bin/kc.sh build
RUN /opt/keycloak/bin/kc.sh show-config

FROM quay.io/keycloak/keycloak:18.0.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
WORKDIR /opt/keycloak
# RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore
ARG DB_VENDOR
ARG DB_ADDR
ARG DB_PORT
ARG DB_DATABASE
ARG DB_USER
ARG DB_PASSWORD
ARG KEYCLOAK_ADMIN
ARG KEYCLOAK_ADMIN_PASSWORD
ENV DB_VENDOR=${DB_VENDOR}
ENV KEYCLOAK_ADMIN=${KEYCLOAK_ADMIN}
ENV KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD}
ENV KC_DB_URL=jdbc:postgresql://${DB_ADDR}:${DB_PORT}/${DB_DATABASE}
ENV KC_DB_USERNAME=${DB_USER}
ENV KC_DB_PASSWORD=${DB_PASSWORD}
ENV KC_HOSTNAME=keycloak.local
#:8080
ENV KC_HOSTNAME_STRICT=false
ENV KC_HTTP_ENABLED=true
ENV KC_HOSTNAME_STRICT_HTTPS=false
ENV KEYCLOAK_LOGLEVEL=debug
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start"]
#, "--proxy", "edge"]
# , "--db","postgres"