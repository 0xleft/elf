FROM ubuntu:latest

RUN apt update && apt install curl -y
COPY /bin/elf /tmp/elf
RUN chmod +x /tmp/elf

ENTRYPOINT ["/bin/bash"]