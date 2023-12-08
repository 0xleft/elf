set -e

# build docker image in .
sudo docker build -t infected-server .

sudo docker run -it --rm -p 4543:4543 infected-server