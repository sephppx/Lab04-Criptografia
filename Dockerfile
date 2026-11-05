FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

# Usuario utilizado para las pruebas del laboratorio
RUN useradd -m -s /bin/bash felipe && \
    echo "felipe:lab04ssh" | chpasswd

# Se genera solamente la clave de host Ed25519 que utilizaremos
RUN rm -f /etc/ssh/ssh_host_* && \
    ssh-keygen -t ed25519 \
    -f /etc/ssh/ssh_host_ed25519_key \
    -N ""

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]