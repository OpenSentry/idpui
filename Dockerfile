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
RUN go get github.com/gin-gonic/gin
RUN go get github.com/gorilla/csrf
RUN go get github.com/gwatts/gin-adapter
RUN go get golang.org/x/oauth2

# Install the package
RUN go install -v ./...

# This container exposes port 8080 to the outside world
EXPOSE 8080

CMD if [ "${APP_ENV}" = "production" ]; \
      then \
        golang-idp-fe; \
      else \
        go get github.com/pilu/fresh && \
        fresh; \
      fi
