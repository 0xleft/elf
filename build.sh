set -e

rm bin/* -rf

cmake .
cmake --build .