FROM ubuntu:16.04

WORKDIR /root

COPY sources.list /etc/apt/sources.list

RUN apt-get update \
    && apt-get install -y software-properties-common \
    && add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update \
	&& apt-get -y install \
		build-essential \
		gcc-multilib \
		libtool \
		automake \
		autoconf \
		bison \
		debootstrap \
		debian-archive-keyring \
		libtool-bin \
		flex \
		git \
		python3.7 \
		python3-pip \
		curl \
		libacl1-dev \
	&& apt-get -y build-dep qemu \
	&& apt-get -y build-dep qemu-system \
	|| exit 1

COPY fuzzer fuzzer
COPY build.sh .
COPY requirements.txt .
COPY pip.conf /root/.pip/pip.conf

RUN ./build.sh
RUN mkdir ~/.pip
RUN curl https://bootstrap.pypa.io/get-pip.py | python3.7 \
    && pip3 install -r requirements.txt \
    || exit 1
