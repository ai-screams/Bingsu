# bash 5.1 and zsh 5.8 (spec section 9, M1 row). Version asserted by check_versions.py.
FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash zsh python3 python3-pexpect python3-pyte python3-pytest \
      strace locales ca-certificates \
 && sed -i 's/^# *\(ko_KR.UTF-8\)/\1/; s/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*
