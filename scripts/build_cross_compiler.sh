#!/bin/bash
set -e

TARGET=x86_64-elf
PREFIX=`pwd`/compiler
PATH=$PATH:$PREFIX/bin
BINUTILS_VERSION=2.36
BINUTILS=binutils-$BINUTILS_VERSION
GCC_VERSION=11.1.0
GCC=gcc-$GCC_VERSION

if [[ ! -d compiler/src ]]
then
	mkdir -p compiler/src
	cd compiler/src

	echo "Downloading sources for $BINUTILS and $GCC"
	wget http://ftp.gnu.org/gnu/binutils/${BINUTILS}.tar.xz
	wget http://ftp.gnu.org/gnu/gcc/${GCC}/${GCC}.tar.xz

	echo "Extracting"
	tar -xf ${BINUTILS}.tar.xz
	tar -xf ${GCC}.tar.xz

	echo "Downloading gcc prerequisites"
	cd $GCC
	./contrib/download_prerequisites

	cd ../../..
fi

ncores=`nproc --all`

echo "Building $BINUTILS"
mkdir -p compiler/build/$BINUTILS
cd compiler/build/$BINUTILS
../../src/$BINUTILS/configure --target=$TARGET --prefix="$PREFIX" \
                              --with-sysroot --disable-nls --disable-werror
make -j$ncores
make install
cd -

echo "Building $GCC"
mkdir -p compiler/build/$GCC
cd compiler/build/$GCC
../../src/$GCC/configure --target=$TARGET --prefix="$PREFIX" --disable-nls \
                         --enable-languages=c,c++ --without-headers
make all-gcc -j$ncores
make all-target-libgcc -j$ncores
make install-gcc
make install-target-libgcc
cd -

echo "Done"