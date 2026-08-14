# Network flow / TCP state tracking Docker test runtime image.
#
# Minimal Alpine-based runtime with the elf-owl binary (eBPF bytecode is embedded
# into the binary at build time via go:embed, so no separate .o files are shipped
# here). Used by test_flow_tracking_docker.sh to verify bidirectional flow
# tracking and kernel TCP state transitions against real TCP traffic.
#
# The test script will:
#   1. Compile pkg/ebpf/programs/*.c to bin/*.o (requires vmlinux.h + clang)
#   2. Build a static CGO_ENABLED=0 elf-owl binary (embeds the .o files)
#   3. Copy this Dockerfile into the build context and build the image
#   4. Run the container --privileged with host BTF mounted, alongside a
#      mock webhook receiver and an nginx target container
#
# Expects the build context to contain:
#   elf-owl    (the CGO_ENABLED=0 static binary)

FROM alpine:3.19
RUN apk add --no-cache ca-certificates

COPY elf-owl /usr/local/bin/elf-owl

EXPOSE 9090 9091

ENTRYPOINT ["/usr/local/bin/elf-owl"]
CMD ["--config", "/etc/elf-owl/elf-owl.yaml"]
