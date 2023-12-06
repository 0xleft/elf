set -e

# build docker image in .
sudo docker build -t infected-server .

sudo docker run -it --rm -p 45435:45435 infected-server