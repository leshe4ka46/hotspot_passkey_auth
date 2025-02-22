FROM node:latest AS frontend-builder
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm i
ADD web .
ARG GIT_COMMIT
ENV REACT_APP_VERSION=$GIT_COMMIT
RUN if [ -z "$REACT_APP_VERSION" ]; then echo "REACT_APP_VERSION is not set or empty, halting build."; exit 1; fi
RUN npm run build


FROM golang:latest AS builder
ENV CGO_ENABLED=0
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache
WORKDIR /auth
COPY go.mod .
COPY go.sum .
RUN --mount=type=cache,target=/gomod-cache \
  go mod download -x

ADD . .
COPY --from=frontend-builder /web/build ./web/build
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache \
    GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o auth .


FROM scratch
COPY --chown=1000:1000 --from=builder /auth/auth /bin/auth
ENV DOCKER_RELEASE=true
CMD ["/bin/auth"]