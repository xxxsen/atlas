FROM golang:1.24

WORKDIR /build
COPY . ./
RUN CGO_ENABLED=0 go build -a -tags netgo -ldflags '-w' -o atlas ./cmd/atlas

FROM alpine:3.12
COPY --from=0 /build/atlas /bin/

ENTRYPOINT [ "/bin/atlas" ]