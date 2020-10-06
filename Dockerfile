FROM golang:latest
LABEL maintainer="qianz 1685437606@qq.com"

RUN apt-get update
RUN apt-get -y install libpcap-dev netcat vim
RUN mkdir /root/go-tcp
COPY ./ /root/go-tcp
RUN go env -w  GOPROXY=https://goproxy.cn,direct 
RUN cd /root/go-tcp/ && go build -v .
