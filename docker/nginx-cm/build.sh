#!/bin/sh
#

VER=1.0
cd ../..
cargo build --release
cd -
cp ../../target/release/nginx-cm .
docker build . -t nginx-cm:latest
docker tag nginx-cm:latest wushilin/nginx-cm:$VER
docker tag nginx-cm:latest wushilin/nginx-cm:latest
docker push wushilin/nginx-cm:$VER
docker push wushilin/nginx-cm:latest
