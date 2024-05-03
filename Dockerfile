FROM golang:latest AS builder

WORKDIR /
ADD . /auth
WORKDIR /auth
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o /bin/auth .

FROM scratch
COPY --chown=1000:1000 --from=builder /bin/auth /bin/auth
CMD ["/bin/auth"]