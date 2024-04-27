FROM ubuntu:20.04 as build

ENV  DEBIAN_FRONTEND=noninteractive

# checkout latest install.md of bcc for ubuntu
RUN apt-get update && \
apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev arping netperf iperf

RUN git clone https://github.com/iovisor/bcc.git
RUN mkdir bcc/build

WORKDIR /bcc/build
RUN cmake ..
RUN make
RUN  make install
RUN cmake -DPYTHON_CMD=python3 .. # build python3 binding

WORKDIR /bcc/build/src/python
RUN make
RUN make install

WORKDIR /usr/sbin/
COPY script.py .

CMD [ "python3", "./script.py" ]