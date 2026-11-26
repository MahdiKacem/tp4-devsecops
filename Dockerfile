# Image de base minimale (variante slim), épinglée par digest et mise à jour par Dependabot.
FROM nginxinc/nginx-unprivileged:mainline-alpine-slim@sha256:a8cb0f33d51fa107c96fd2bd3a71aaf564ec131e9d2bdf8700944f0ed8b170d7

# Applique les correctifs Alpine publiés après la construction de l'image amont
# (le scan Trivy de l'image bloque sinon la signature sur des CVE HIGH/CRITICAL corrigées).
USER root
RUN apk upgrade --no-cache

COPY --chown=101:101 app/ /usr/share/nginx/html/

USER 101:101

EXPOSE 8080
