#!/usr/bin/env bash

# ==================================================================
# Build QEMU for each architectures
# ==================================================================

DIR=$(dirname $(realpath $0))
RESOURCES_DIR=${DIR}/fuzzer/resources
AFL_UNIX_REPO=https://github.com/shellphish/afl-other-arch
AFL_UNIX_PATH=${RESOURCES_DIR}/bin/afl-unix
AFL_UNIX_PATCHES_DIR=${RESOURCES_DIR}/patches/afl-unix
SUPPORTED_ARCHITECTURES="aarch64 x86_64 i386 arm ppc ppc64 mips mipsel mips64"
QEMU_VERSION="2.10.0"
QEMU_URL="https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz"
QEMU_SHA384="68216c935487bc8c0596ac309e1e3ee75c2c4ce898aab796faa321db5740609ced365fedda025678d072d09ac8928105"
ARCHIVE="`basename -- "$QEMU_URL"`"

pushd ${DIR}  # project root

if [[ ! -d ${AFL_UNIX_PATH} ]]; then
    git clone ${AFL_UNIX_REPO} ${AFL_UNIX_PATH} \
        && patch -d ${AFL_UNIX_PATH} -p0 < ${AFL_UNIX_PATCHES_DIR}/afl-patch.diff \
        || exit 1
fi

pushd ${AFL_UNIX_PATH}  # fuzzer/resources/bin/afl-unix

if [[ ! "`uname -s`" = "Linux" ]]; then
  echo "[-] Error: QEMU instrumentation is supported only on Linux."
  exit 1
fi

if [[ ! -d "/usr/include/glib-2.0/" && ! -d "/usr/local/include/glib-2.0/" ]]; then
  echo "[-] Error: dev version of 'glib2' not found, please install first."
  exit 1
fi

# Compile afl-unix
make

pushd qemu_mode  # fuzzer/resources/bin/afl-unix/qemu_mode

if [[ ! -f ${ARCHIVE} ]]; then
    echo "[*] Downloading QEMU ${QEMU_VERSION}..."
    wget -O "$ARCHIVE" -- "$QEMU_URL" || exit 1
fi
CHECKSUM=`sha384sum -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`

if [[ ! "$CHECKSUM" = "$QEMU_SHA384" ]]; then
    echo "[-] Error: Invalid checksum for QEMU ${QEMU_VERSION} on ${ARCHIVE}."
    exit 1
fi

rm -rf "qemu-${QEMU_VERSION}" \
    && echo -n "[*] Extracting ${ARCHIVE}..." \
    && tar xf "$ARCHIVE" \
    && echo "Done" \
    || exit 1

pushd qemu-${QEMU_VERSION}  # fuzzer/resources/bin/afl-unix/qemu_mode/qemu-${QEMU_VERSION}

patch -p1 < ../patches/elfload.diff \
    && patch -p1 < ../patches/cpu-exec.diff \
    && patch -p1 < ../patches/syscall.diff \
    || exit 1

mkdir -p ${RESOURCES_DIR}/bin
for ARCH in ${SUPPORTED_ARCHITECTURES}; do
    echo -n "[*] Configuring QEMU for ${ARCH}..."
    CFLAGS="-O3 -ggdb -w" ./configure \
        --disable-system \
        --python=`which python2` \
        --enable-linux-user \
        --disable-gtk \
        --disable-sdl \
        --disable-vnc \
        --target-list="${ARCH}-linux-user" \
        --enable-pie \
        --enable-kvm > /dev/null\
        && make -j$(nproc) > /dev/null \
        && cp -f "${ARCH}-linux-user/qemu-${ARCH}" "${RESOURCES_DIR}/bin" \
        || exit 1
    echo "Done"
done

popd # fuzzer/resources/bin/afl-unix/qemu_mode
popd # fuzzer/resources/bin/afl-unix

make -j$(nproc) > /dev/null

popd # project root
popd # pwd

# ==================================================================
# Fetch architecture libraries
# ==================================================================

DEBOOTSTRAP_DIR=/usr/share/debootstrap
UBUNTU_KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg
DEBIAN_KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
LIBS="libc-bin libstdc++6"

if [[ ! -d "$DEBOOTSTRAP_DIR" ]] || [[ ! -f "$DEBIAN_KEYRING" ]]; then
  echo "this script requires debootstrap and debian-archive-keyring to be installed"
  exit 1
fi

fetch_arch() {
  ARCH="$1"
  DISTRO="$2"
  SUITE="$3"
  exec 4>&1
  SHA_SIZE=256
  DEBOOTSTRAP_CHECKSUM_FIELD="SHA$SHA_SIZE"
  TARGET="$ARCH"
  TARGET="$(echo "`pwd`/$TARGET")"
  HOST_ARCH=`/usr/bin/dpkg --print-architecture`
  HOST_OS=linux
  USE_COMPONENTS=main
  RESOLVE_DEPS=true
  export DEBOOTSTRAP_CHECKSUM_FIELD

  mkdir -p "${TARGET}" "${TARGET}/debootstrap"

  . ${DEBOOTSTRAP_DIR}/functions
  . ${DEBOOTSTRAP_DIR}/scripts/${SUITE}

  if [[ ${DISTRO} == "ubuntu" ]]; then
    KEYRING=${UBUNTU_KEYRING}
    MIRRORS="${DEF_MIRROR}"
  elif [[ ${DISTRO} == "debian" ]]; then
    KEYRING=${DEBIAN_KEYRING}
    MIRRORS="http://ftp.us.debian.org/debian"
  else
    echo "need a distro"
    exit 1
  fi

  download_indices
  work_out_debs

  all_debs=$(resolve_deps ${LIBS})
  echo "$all_debs"
  download ${all_debs}

  choose_extractor
  extract ${all_debs}
}

ARCHES="armhf armel powerpc arm64 i386 mips mipsel"
for ARCH in ${ARCHES}; do
    LIB_DIR="${RESOURCES_DIR}/bin/fuzzer-libs/${ARCH}"
    if [[ ! -d ${LIB_DIR} ]]; then
        mkdir -p ${LIB_DIR}
        pushd ${RESOURCES_DIR}/bin/fuzzer-libs
        case "${ARCH}" in
            armhf)
                fetch_arch armhf ubuntu trusty
                ;;
            armel)
                fetch_arch armel debian jessie
                ;;
            powerpc)
                fetch_arch powerpc ubuntu trusty
                ;;
            arm64)
                fetch_arch arm64 ubuntu trusty
                ;;
            i386)
                fetch_arch i386 ubuntu trusty
                ;;
            mips)
                fetch_arch mips debian jessie
                ;;
            mipsel)
                fetch_arch mipsel debian jessie
                ;;
        esac
        popd
    fi
done

# ==================================================================
# Build QEMU with tracer patches
# ==================================================================
TRACER_QEMU_REPO="https://github.com/qemu/qemu.git"
TRACER_QEMU_DIR=${RESOURCES_DIR}/bin/qemu
TRACER_PATCHES_DIR=${RESOURCES_DIR}/patches/tracer

pushd ${DIR} # project root

mkdir -p ${RESOURCES_DIR}/bin/tracers || exit 1
if [[ ! -d ${TRACER_QEMU_DIR} ]]; then
    git clone --branch v2.3.0 --depth=1 ${TRACER_QEMU_REPO} ${TRACER_QEMU_DIR} \
        && git -C ${TRACER_QEMU_DIR} apply ${TRACER_PATCHES_DIR}/tracer-qemu.patch \
        && git -C ${TRACER_QEMU_DIR} apply ${TRACER_PATCHES_DIR}/ucontext.patch \
        && git -C ${TRACER_QEMU_DIR} apply ${TRACER_PATCHES_DIR}/linux-coredump.patch \
        || exit 1
fi


pushd ${TRACER_QEMU_DIR} # bin/qemu

# tracer-qemu.patch creates `tracer-config` script

./tracer-config \
    && make clean \
    && make -j$(nproc) \
    && for ARCH in ${SUPPORTED_ARCHITECTURES}; do cp ${ARCH}-linux-user/qemu-${ARCH} ../tracers/qemu-${ARCH} || exit 1; done \
    && chmod 755 ../tracers/qemu-* \
    || exit 1

popd # project root
popd # pwd
