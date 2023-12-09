set -e

rm bin/* -rf

#ld preload glibc
# get it from here if you dont have it https://hub.docker.com/r/skysider/glibc_builder64/
export PATH=/mnt/d/glibc/glibc-2.27/bin:$PATH

echo "Using glibc version:"
ldd --version

cmake .
cmake --build .