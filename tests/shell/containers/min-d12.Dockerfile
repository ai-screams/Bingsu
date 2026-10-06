# fish 3.6 (spec section 5 minimum). Version asserted by check_versions.py.
FROM debian:12@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends fish python3 python3-pexpect python3-pyte python3-pytest \
      strace locales ca-certificates \
 && sed -i 's/^# *\(ko_KR.UTF-8\)/\1/; s/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*
