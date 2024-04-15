FROM alpine:3.8
RUN apk add --update \
    bash \
    bc \
    build-base \
    python3 \
    bison \
    flex \
    curl \
    elfutils-dev \
    linux-headers \
    make \
    openssl-dev

WORKDIR /

COPY ./fetch-linux-headers.sh  /
RUN chmod +x fetch-linux-headers.sh
ENTRYPOINT [ "/fetch-linux-headers.sh" ]