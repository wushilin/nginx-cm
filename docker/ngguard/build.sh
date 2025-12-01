#!/bin/sh
#
VER=1.0
cd ../..
cargo build --release
cd -
cp ../../target/release/ngguard .
docker build . -t ngguard:latest
docker tag ngguard:latest wushilin/ngguard:$VER
docker tag ngguard:latest wushilin/ngguard:latest
docker push wushilin/ngguard:$VER
docker push wushilin/ngguard:latest
