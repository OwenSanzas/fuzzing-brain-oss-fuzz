# Copyright 2018 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y cmake bison flex
RUN git clone --depth 50 https://github.com/igraph/igraph && \
    cd igraph && \
    git fetch --unshallow && \
    git fetch --tags && \
    git checkout 0.10.10
WORKDIR igraph
RUN sed -i '/# Build igraph/a echo "0.10.14-dev" > $SRC/igraph/IGRAPH_VERSION' $SRC/igraph/fuzzing/build.sh
RUN sed -i '/if (igraph_read_graph_gml(&g, ifile) == IGRAPH_SUCCESS) {/a\\n        FILE *ofile = fopen("/dev/null", "w");\n        if (ofile) {\n            igraph_write_graph_gml(&g, ofile, IGRAPH_WRITE_GML_DEFAULT_SW, NULL, NULL);\n            fclose(ofile);\n        }\n' $SRC/igraph/fuzzing/read_gml.cpp
RUN cp $SRC/igraph/fuzzing/build.sh $SRC/build.sh
