FROM ubuntu:24.04
RUN apt update
RUN apt install -y nginx libnginx-mod-stream
RUN mkdir /nginx-cm
COPY nginx-cm /nginx-cm/nginx-cm
RUN chmod +x /nginx-cm/nginx-cm
WORKDIR /nginx-cm
ENTRYPOINT ["/nginx-cm/nginx-cm"]
