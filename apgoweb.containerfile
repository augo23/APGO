# APGO marketing website (static nginx). Build from the REPO ROOT as the context:
#   podman build -f apgoweb.containerfile -t apgoweb:latest .
# Your pipeline pushes it as registry.kube.sunairies.com/apgoweb:latest.
FROM nginx:alpine
COPY website/site/ /usr/share/nginx/html/
