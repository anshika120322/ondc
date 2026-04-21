# syntax=docker/dockerfile:1
ARG AFAAS_IST_DOCKER_REGISTRY=${AFAAS_IST_DOCKER_REGISTRY:-kyndryl.jfrog.io/kyn-ist-reg-docker-local}
ARG IMAGE_VERSION=${IMAGE_VERSION:-latest}

FROM ${AFAAS_IST_DOCKER_REGISTRY}/common-test-foundation:${IMAGE_VERSION}

ARG ARTIFACTORY_CREDS=${ARTIFACTORY_CREDS}
ARG AFAAS_IST_PYPI_REGISTRY=${AFAAS_IST_PYPI_REGISTRY}

WORKDIR /app

COPY requirements.txt requirements.txt

RUN --mount=type=ssh pip install --no-cache-dir -r requirements.txt --extra-index-url=https://${ARTIFACTORY_CREDS}@${AFAAS_IST_PYPI_REGISTRY}/simple

COPY . .
