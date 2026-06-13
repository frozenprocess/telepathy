# syntax=docker/dockerfile:1
#
# Two-stage build for telepathy.
#
#   stage 1 (build):   compile the Linux binaries with the project Makefile
#   stage 2 (runtime): copy the static binaries into a minimal base image
#
# `make build` produces two binaries: the `telepathy` shell (Calico in-process)
# and the out-of-process `telepathy-engine-antrea` engine. Both are copied into
# the same directory so the shell finds the engine automatically (proxy.go).
#
# The engine imports Linux-only Calico/Felix packages, so the image is always
# linux/<arch>. That still runs on macOS and Windows hosts *through Docker*,
# which is the point of shipping it as an image rather than a host binary.

# --- build stage -----------------------------------------------------------
ARG GO_VERSION=1.25.6
FROM golang:${GO_VERSION} AS build

# CGO off keeps the binary static (no libbpf headers needed) and makes the
# Calico cross-platform stubs kick in; GOTOOLCHAIN=auto lets the workspace
# pull whatever Go version go.work / go.mod pins, even if it exceeds the image.
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto \
    GOOS=linux

# BuildKit populates TARGETARCH from --platform (or the host default), so the
# binary matches the image arch — e.g. arm64 on Apple Silicon, amd64 elsewhere.
ARG TARGETARCH
ENV GOARCH=${TARGETARCH}

# Version metadata is computed on the host (where .git lives) and passed in,
# so .git can stay out of the build context.
ARG ENGINE_VERSION=dev
ARG GIT_COMMIT=unknown
ENV ENGINE_VERSION=${ENGINE_VERSION} \
    GIT_COMMIT=${GIT_COMMIT}

WORKDIR /src
COPY . .

# `make build` clones the pinned Calico tree, wires up go.work, and builds.
# git + make are already present in the Debian-based golang image.
RUN make build

# --- runtime stage ---------------------------------------------------------
# distroless/static = libc-free, shell-free base with CA certs + tzdata, ideal
# for a statically linked Go binary. The engine is a stdin->stdout filter.
FROM scratch

COPY --from=build /src/bin/telepathy /usr/local/bin/telepathy
COPY --from=build /src/bin/telepathy-engine-antrea /usr/local/bin/telepathy-engine-antrea

ENTRYPOINT ["/usr/local/bin/telepathy"]
