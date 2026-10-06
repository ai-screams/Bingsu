# Current distribution shells (bash, zsh, fish). Versions are recorded, not asserted.
FROM debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash zsh fish python3 python3-pexpect python3-pyte python3-pytest \
      strace locales ca-certificates \
 && sed -i 's/^# *\(ko_KR.UTF-8\)/\1/; s/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen \
 && printf '%s\n' 'fa_IR.UTF-8 UTF-8' 'ps_AF.UTF-8 UTF-8' >> /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*
