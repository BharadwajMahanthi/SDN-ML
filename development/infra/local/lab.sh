#!/usr/bin/env bash
# The Linux lab, on whatever machine you are sitting at.
#
#   ./lab.sh build          build the image
#   ./lab.sh shell          interactive root shell with the repo mounted
#   ./lab.sh caps           what this kernel can actually verify
#   ./lab.sh test           run the response suite against a real kernel
#   ./lab.sh run <cmd...>   run one command in the lab
#
# On macOS this uses Docker Desktop's Linux VM, which is a real kernel. On
# Linux it uses the host kernel directly. The image and the commands are the
# same in both cases, which is the point.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE="annulon-lab:local"
# NET_ADMIN is what nftables needs. The container is not given blanket
# privilege by default: an experiment that needs more must say so, out loud.
DOCKER_ARGS=(--rm --cap-add=NET_ADMIN --network=bridge
             -v "${REPO_ROOT}:/annulon:ro"
             -e PYTHONPATH=/annulon/development/src
             -w /annulon)

usage() { sed -n '2,12p' "$0"; exit "${1:-1}"; }

require_docker() {
  command -v docker >/dev/null || { echo "docker not found" >&2; exit 2; }
  docker info >/dev/null 2>&1 || {
    echo "the Docker daemon is not running (start Docker Desktop)" >&2; exit 2; }
}

cmd="${1:-}"; shift || true
case "$cmd" in
  build) require_docker
         docker build -t "$IMAGE" "${REPO_ROOT}/development/infra/local" ;;
  shell) require_docker
         docker run -it "${DOCKER_ARGS[@]}" "$IMAGE" /bin/bash ;;
  caps)  require_docker
         docker run "${DOCKER_ARGS[@]}" "$IMAGE" \
           python3 development/infra/local/capabilities.py "$@" ;;
  test)  require_docker
         docker run "${DOCKER_ARGS[@]}" "$IMAGE" \
           python3 -m pytest development/tests/response -q -p no:cacheprovider "$@" ;;
  run)   require_docker
         [ $# -gt 0 ] || usage
         docker run "${DOCKER_ARGS[@]}" "$IMAGE" "$@" ;;
  ""|-h|--help) usage 0 ;;
  *) echo "unknown command: $cmd" >&2; usage ;;
esac
