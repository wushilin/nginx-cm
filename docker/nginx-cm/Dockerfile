FROM ubuntu:24.04
RUN apt update && apt install -y ca-certificates nginx libnginx-mod-stream && rm -rf /var/lib/apt/lists/*
RUN mkdir /nginx-cm
COPY nginx-cm /nginx-cm/nginx-cm
RUN chmod +x /nginx-cm/nginx-cm
WORKDIR /nginx-cm
EXPOSE 3000
ENTRYPOINT ["/nginx-cm/nginx-cm"]
