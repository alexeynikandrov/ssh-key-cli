FROM ubuntu:24.04 

ENV TZ=Asia/Jerusalem
ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && \
    apt-get install -y \
    sudo \
    apt-utils \
    openssh-server  && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd && \
    echo "ALL ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/allow-all && \
    echo 'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' >> /etc/sudoers.d/allow-all && \
    chmod 0440 /etc/sudoers.d/allow-all && \
    sed -i 's/#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#\?PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
