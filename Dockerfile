FROM golang:1.15 as build

WORKDIR /go/src/github.com/webdevops/apprelease-exporter

# Get deps (cached)
COPY ./go.mod /go/src/github.com/webdevops/apprelease-exporter
COPY ./go.sum /go/src/github.com/webdevops/apprelease-exporter
RUN go mod download

# Compile
COPY ./ /go/src/github.com/webdevops/apprelease-exporter
RUN make test
RUN make lint
RUN make build
RUN ./apprelease-exporter --help

#############################################
# FINAL IMAGE
#############################################
FROM gcr.io/distroless/static
ENV LOG_JSON=1
COPY --from=build /go/src/github.com/webdevops/apprelease-exporter/apprelease-exporter /
USER 1000
ENTRYPOINT ["/apprelease-exporter"]
