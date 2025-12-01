FROM ubuntu:24.04
RUN apt update && apt install -y ca-certificates nginx libnginx-mod-stream && rm -rf /var/lib/apt/lists/*
RUN mkdir /ngguard
COPY ngguard /ngguard/ngguard
RUN chmod +x /ngguard/ngguard
WORKDIR /ngguard
EXPOSE 443 9092
ENTRYPOINT ["/ngguard/ngguard"]
