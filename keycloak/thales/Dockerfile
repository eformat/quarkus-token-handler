FROM jboss/keycloak:15.1.0

USER root

RUN mkdir -p /opt/jboss/keycloak/standalone/tmp/vfs \
 && chmod g+r -vfR /opt/jboss/keycloak/standalone \
 && chmod g+w -vf /opt/jboss/keycloak/standalone/{.,deployments} \
 && chmod g+w -vfR /opt/jboss/keycloak/standalone/{tmp,configuration,log} \
 && chgrp 0 -vfR /opt/jboss/keycloak/standalone

ENV PROXY_ADDRESS_FORWARDING=true

RUN echo "security.provider.13=com.safenetinc.luna.provider.LunaProvider" >> /etc/java/java-11-openjdk/java-11-openjdk-11.0.13.0.8-3.el8_5.x86_64/conf/security/java.security
RUN mkdir -p /opt/lunastore
VOLUME /opt/lunastore

USER jboss

ADD realm.json /tmp/bff-realm.json
ADD auth-entrypoint.sh /opt/jboss/auth-entrypoint.sh

ENV KEYCLOAK_USER=admin
ENV KEYCLOAK_PASSWORD=password

ENTRYPOINT [ "/opt/jboss/auth-entrypoint.sh" ]

RUN mkdir -p /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/keycloak/provider/main
RUN mkdir -p /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/main/lib/linux-x86_64
RUN mkdir -p /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/keycloak/provider/main/lib/linux-x86_64

COPY patch/630-000513-001_SW_Patch_keycloak_UC_Clnt_10.3.0_Custom_Release/linux/64/LunaProvider.jar /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/main/
COPY patch/630-000513-001_SW_Patch_keycloak_UC_Clnt_10.3.0_Custom_Release/linux/64/libLunaAPI.so /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/main/lib/linux-x86_64/
COPY module.xml /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/main/
COPY patch/com/safenetinc/luna/keycloak/provider/keycloak-spi-luna-keystore-1.0.jar /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/keycloak/provider/main/
COPY patch/com/safenetinc/luna/keycloak/provider/module.xml /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc/luna/keycloak/provider/main/
COPY standalone.xml /opt/jboss/keycloak/standalone/configuration/standalone.xml

USER root
RUN chown -R jboss:root /opt/jboss/keycloak/modules/system/layers/keycloak/com/safenetinc
USER jboss

CMD ["-b", "0.0.0.0", "-Dkeycloak.migration.action=import", "-Dkeycloak.migration.provider=singleFile", "-Dkeycloak.migration.strategy=IGNORE_EXISTING", "-Dkeycloak.migration.file=/tmp/bff-realm.json"]
