FROM golang:1.14 as build

WORKDIR /go/src/github.com/webdevops/apprelease-exporter

# Get deps (cached)
COPY ./go.mod /go/src/github.com/webdevops/apprelease-exporter
COPY ./go.sum /go/src/github.com/webdevops/apprelease-exporter
RUN go mod download

# Compile
COPY ./ /go/src/github.com/webdevops/apprelease-exporter
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o /apprelease-exporter \
    && chmod +x /apprelease-exporter
RUN /apprelease-exporter --help

#############################################
# FINAL IMAGE
#############################################
FROM gcr.io/distroless/static
COPY --from=build /apprelease-exporter /
USER 1000
ENTRYPOINT ["/apprelease-exporter"]
