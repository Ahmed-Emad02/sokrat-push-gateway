# Sokrat Push Gateway & Multi-Tenant Provisioning Container
# Multi-stage production image for Ubuntu/Debian/Rocky VPS
FROM node:20-bookworm-slim AS node-deps

WORKDIR /opt/sokrat-push-gateway
COPY package*.json ./
RUN npm ci --omit=dev

FROM debian:bookworm-slim

LABEL maintainer="Sokrat Suite Ops <ops@sokrat.io>"
LABEL description="Sokrat Push Gateway, Control Dashboard & Tenant Provisioning Engine"

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    gettext-base \
    procps \
    net-tools \
    iproute2 \
    iptables \
    ufw \
    openssh-client \
    coturn \
    nginx \
    supervisor \
    python3 \
    python3-pip \
    python3-paramiko \
    python3-cryptography \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ARG SOKRAT_UID=999
ARG SOKRAT_GID=999

RUN groupadd -g ${SOKRAT_GID} sokrat-push && \
    useradd -u ${SOKRAT_UID} -g ${SOKRAT_GID} -s /usr/sbin/nologin -d /opt/sokrat-push-gateway sokrat-push

RUN mkdir -p /opt/sokrat-push-gateway \
             /usr/local/lib/sokrat-tenant-provisioning \
             /etc/sokrat/ssh \
             /etc/sokrat/turn \
             /var/lib/sokrat-gateway/secrets \
             /var/lib/sokrat-tenant-provisioning \
             /run/sokrat-tenant-onboarding \
             /run/sokrat-tenant-provisioning \
             /var/log/sokrat \
             /var/log/supervisor \
             /etc/supervisor/conf.d

RUN chown -R sokrat-push:sokrat-push /var/lib/sokrat-gateway \
    && chown root:sokrat-push /run/sokrat-tenant-onboarding \
    && chmod 0750 /run/sokrat-tenant-onboarding \
    && chown root:sokrat-push /var/lib/sokrat-tenant-provisioning \
    && chmod 0750 /var/lib/sokrat-tenant-provisioning \
    && chmod 0700 /etc/sokrat/ssh

WORKDIR /opt/sokrat-push-gateway

COPY --from=node-deps --chown=sokrat-push:sokrat-push /opt/sokrat-push-gateway/node_modules ./node_modules
COPY --chown=sokrat-push:sokrat-push . .

RUN cp scripts/reconcile-tenant-provisioning.py /usr/local/lib/sokrat-tenant-provisioning/ && \
    cp scripts/sync-tenant-runtime.py /usr/local/lib/sokrat-tenant-provisioning/ && \
    cp scripts/provisioning-onboarding.py /usr/local/lib/sokrat-tenant-provisioning/ && \
    cp scripts/provisioning-hook-ssh.py /usr/local/lib/sokrat-tenant-provisioning/ && \
    cp scripts/install-tenant-push-hook.py /usr/local/lib/sokrat-tenant-provisioning/ && \
    cp scripts/pbx-tenant-push-hook.py /usr/local/lib/sokrat-tenant-provisioning/ && \
    cp scripts/tunnel_media.py scripts/check-tunnel-readiness.py /usr/local/lib/sokrat-tenant-provisioning/ && \
    chmod 0755 /usr/local/lib/sokrat-tenant-provisioning/*.py && \
    chown -R root:root /usr/local/lib/sokrat-tenant-provisioning

COPY docker/systemctl-shim.py /usr/local/bin/systemctl
RUN chmod 0755 /usr/local/bin/systemctl && ln -sf /usr/local/bin/systemctl /usr/bin/systemctl && ln -sf /usr/local/bin/systemctl /bin/systemctl

COPY docker/provisioning-firewall-local.py /usr/local/lib/sokrat-tenant-provisioning/provisioning-firewall-local.py
RUN chmod 0755 /usr/local/lib/sokrat-tenant-provisioning/provisioning-firewall-local.py

COPY docker/reconcile-loop.sh /usr/local/bin/reconcile-loop.sh
RUN chmod 0755 /usr/local/bin/reconcile-loop.sh

COPY docker/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/nginx-gateway.conf.template /etc/nginx/templates/sokrat.conf.template
COPY docker/nginx-wss.conf /etc/nginx/templates/sokrat-tls.conf.template
COPY docker/configure-gateway-tls.sh /usr/local/bin/configure-gateway-tls.sh
RUN chmod 0755 /usr/local/bin/configure-gateway-tls.sh
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 80 443 8002 8088 8089 8095 9096 9097 3478/tcp 3478/udp 3479/tcp 3479/udp

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
