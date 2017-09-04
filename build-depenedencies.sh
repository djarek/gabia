#!/bin/bash

prefix=$1

if [ -z $prefix ]; then
    prefix='/usr/local'
fi

(cd external/wolfssl \
&& ./autogen.sh \
&& ./configure \
    --prefix=$prefix \
    --disable-examples \
    --disable-sha224 \
    --enable-srp \
    --enable-curve25519 \
    --enable-ed25519 \
    --enable-poly1305 \
    --enable-hkdf \
    --enable-sha512 \
&& make -j2 \
&& make install) || exit $?

(cd external/GSL \
&& mkdir build \
&& cd build \
&& cmake -DCMAKE_INSTALL_PREFIX:PATH=$prefix .. \
&& make install) || exit $?

(cd external/beast \
&& cp -r include/* $prefix/include/ \
&& cp -r test/extras/include/* $prefix/include/) || exit $?
