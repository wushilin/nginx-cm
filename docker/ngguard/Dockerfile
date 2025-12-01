FROM ubuntu:24.04
RUN apt update
RUN apt install -y nginx libnginx-mod-stream
RUN mkdir /ngguard
COPY ngguard /ngguard/ngguard
RUN chmod +x /ngguard/ngguard
WORKDIR /ngguard
ENTRYPOINT ["/ngguard/ngguard"]
