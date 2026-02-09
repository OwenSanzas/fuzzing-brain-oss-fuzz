#!/bin/bash -eu
# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Build pcre dependency to be linked statically.
pushd $SRC/pcre2
./autogen.sh
if [ "$SANITIZER" == "introspector" ]; then
  # Disable sanitizers for introspector for pcre. We only care about njs and it's blocking the build.
  CFLAGS="" CXXFLAGS="" LIB_FUZZING_ENGINE="" ./configure
else
  CFLAGS="$CFLAGS -fno-use-cxa-atexit" CXXFLAGS="$CXXFLAGS -fno-use-cxa-atexit" ./configure
fi
make -j$(nproc) clean
make -j$(nproc) all
make install
sed -i "s/\$libS\$libR \(-lpcre2-8$\)/\$libS\$libR -Wl,-Bstatic \1 -Wl,-Bdynamic/" /usr/local/bin/pcre2-config
popd

# build project
rm -rf build

./configure
make njs_fuzzer

cp ./build/njs_process_script_fuzzer $OUT/

SEED_CORPUS_PATH=$OUT/njs_process_script_fuzzer_seed_corpus
mkdir -p $SEED_CORPUS_PATH

set +x
cat src/test/njs_unit_test.c \
    | egrep -o '".*"' | awk '{print substr($0,2,length($0)-2)}' | sort | uniq \
    | while IFS= read -r line; do
      echo $line > $SEED_CORPUS_PATH/$(echo $line | sha1sum | awk '{ print $1 }');
    done

find test/ -name *.t.js \
    | while IFS= read -r testname; do
        cp $testname $SEED_CORPUS_PATH/$(echo $testname | sha1sum | awk '{ print $1 }');
      done
set -x

zip -q $SEED_CORPUS_PATH.zip $SEED_CORPUS_PATH
rm -rf $SEED_CORPUS_PATH

# Common link flags for additional fuzzers
NJS_LINK_LIBS="-lm -L/usr/local/lib -Wl,-Bstatic -lpcre2-8 -Wl,-Bdynamic -lcrypto -lxml2 -lz"

# Build fuzz_webcrypto - targets WebCrypto API
$CC $CFLAGS -Isrc -Iexternal -Ibuild \
    -I/usr/local/include \
    -c $SRC/fuzz_webcrypto.c \
    -o build/fuzz_webcrypto.o

$CXX $CXXFLAGS \
    build/fuzz_webcrypto.o \
    build/libnjs.a \
    $LIB_FUZZING_ENGINE \
    $NJS_LINK_LIBS \
    -o $OUT/fuzz_webcrypto

# Build fuzz_xml - targets XML module (libxml2)
$CC $CFLAGS -Isrc -Iexternal -Ibuild \
    -I/usr/local/include \
    $(pkg-config --cflags libxml-2.0 2>/dev/null || echo "-I/usr/include/libxml2") \
    -c $SRC/fuzz_xml.c \
    -o build/fuzz_xml.o

$CXX $CXXFLAGS \
    build/fuzz_xml.o \
    build/libnjs.a \
    $LIB_FUZZING_ENGINE \
    $NJS_LINK_LIBS \
    -o $OUT/fuzz_xml

# Build fuzz_zlib - targets zlib module
$CC $CFLAGS -Isrc -Iexternal -Ibuild \
    -I/usr/local/include \
    -c $SRC/fuzz_zlib.c \
    -o build/fuzz_zlib.o

$CXX $CXXFLAGS \
    build/fuzz_zlib.o \
    build/libnjs.a \
    $LIB_FUZZING_ENGINE \
    $NJS_LINK_LIBS \
    -o $OUT/fuzz_zlib
