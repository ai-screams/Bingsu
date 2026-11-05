# Command cgroup cells (M6 C3): python test tools, a FUSE mount for the
# survivor fixture and strace for the helper's command stage counts. Run once as a default container (negative cell) and once
# privileged (the atomic path).
FROM debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pexpect python3-pytest bindfs fuse3 strace \
 && rm -rf /var/lib/apt/lists/*
