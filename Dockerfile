# Dockerfile References: https://docs.docker.com/engine/reference/builder/

# Start from golang v1.11 base image
FROM golang:1.12-alpine

# Add Maintainer Info
LABEL maintainer="Lasse Nielsen <65roed@gmail.com>"

RUN apk add --update --no-cache ca-certificates cmake make g++ openssl-dev git curl pkgconfig

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY . .

RUN go build -o idpui .

# This container exposes port 443 to the docker network
EXPOSE 443

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

#USER 1000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["idpui"]
