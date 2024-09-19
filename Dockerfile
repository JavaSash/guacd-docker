FROM ubuntu:20.04

# Environment variables
ENV GUAC_VERSION=0.9.9 \
    LC_ALL=C.UTF-8
# Устанавливаем переменные окружения для бесшумной установки tzdata
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
# Чтобы warnings не трактовались как ошибки
ENV CFLAGS="-Wno-unused"

# Update and install dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends -y patch curl \
        libcairo2-dev \
        fonts-dejavu \
        freerdp2-dev \
        gcc \
        ghostscript \
        libjpeg-turbo8-dev \
        libssh2-1-dev \
        fonts-liberation \
        libtelnet-dev \
        libvorbis-dev \
        libvncserver-dev \
        libwebp-dev \
        make \
        libpango1.0-dev \
        pulseaudio-utils \
        tar \
        fonts-terminus \
        uuid-dev \
        curl \
        ca-certificates \
		libssl-dev \
		libcurl4-openssl-dev \
		libpcre3-dev \
        libossp-uuid-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add configuration scripts
COPY bin /opt/guacd/bin/
COPY openssl_compatibility.patch /tmp/openssl_compatibility.patch
# В этих 2х файлх на С были ошибки из-за обновления версий, пришлось их переписать на вызов актуальных функций
# Далее в скрипте download-guacd.sh мы меняем нерабочие на актуальные файлы
COPY bin/guac_ssh_key.c /tmp/guac_ssh_key.c
COPY bin/ssh_client.c /tmp/ssh_client.c

# Download and install latest guacamole-server
RUN /opt/guacd/bin/download-guacd.sh "$GUAC_VERSION"

# Start guacd, listening on port 0.0.0.0:4822
EXPOSE 4822
CMD [ "/usr/local/sbin/guacd", "-b", "0.0.0.0", "-f" ]
