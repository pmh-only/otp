FROM golang:1.26-alpine AS build
WORKDIR /src
RUN go install github.com/microsoft/typescript-go/cmd/tsgo@latest
COPY go.mod tsconfig.json ./
COPY frontend ./frontend
COPY public ./public
RUN tsgo -p tsconfig.json
COPY *.go ./
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /otp-inbox .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /otp-inbox /otp-inbox
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/otp-inbox"]
