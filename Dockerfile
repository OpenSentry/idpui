# Dockerfile References: https://docs.docker.com/engine/reference/builder/

# Start from golang v1.11 base image
FROM golang:1.12-alpine

# Add Maintainer Info
LABEL maintainer="Lasse Nielsen <65roed@gmail.com>"

RUN apk add --update --no-cache ca-certificates cmake make g++ openssl-dev git curl pkgconfig

# Set the Current Working Directory inside the container
WORKDIR $GOPATH/src/golang-idp-fe

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY . .

# Download all the dependencies
# https://stackoverflow.com/questions/28031603/what-do-three-dots-mean-in-go-command-line-invocations
RUN go get -d -v ./...

# Install the package
RUN go install -v ./...

# This container exposes port 443 to the docker network
EXPOSE 443

#USER 1000

ARG release_build=1
ENV release_build=$release_build

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["golang-idp-fe"]
