#!/usr/bin/env nix-shell
#!nix-shell --pure --keep REGISTRY_ENDPOINT --keep REGISTRY_USERNAME --keep REGISTRY_PASSWORD -i bash -p coreutils busybox apko melange bubblewrap yq-go
#
# Builds and uploads the container image to a private repository.
# @author Gerolf Vent <dev@gerolfvent.de>
# @see https://github.com/chainguard-dev/apko/tree/main/docs
# @see https://github.com/chainguard-dev/melange/tree/main/docs
#
# This script requires the following tools:
# - coreutils
# - busybox
# - apko       (https://github.com/chainguard-dev/apko)
# - melange    (https://github.com/chainguard-dev/melange)
# - bubblewrap
# - yq         (https://github.com/mikefarah/yq)
#

# Check if being run correctly
(return 0 2> /dev/null) && { printf "Error: Sourcing not supported\n"; return 1; }

BASE_PATH="$(dirname "$(readlink -f "$0")")"
cd "$BASE_PATH"

#
# Check dependencies
#

bin_error=false
for bin in apko melange yq; do
    if ! command -v "$bin" &> /dev/null; then
        print_error "'$bin' is not installed."
        bin_error=true
    else
        case "$bin" in
            yq)
                if ! yq -V | grep 'mikefarah' &> /dev/null; then
                    print_error "'$bin' is not from 'mikefarah'."
                    bin_error=true
                fi
                ;;
        esac
    fi
done
[[ "$bin_error" == true ]] && exit 1

#
# Print usage
#

function print_usage() {
    echo "Usage: $0"
    echo
    echo "  Builds and uploads the container images in this repository."
    echo
    echo "Environment variables:"
    echo "  REGISTRY_ENDPOINT     The endpoint of the registry to upload to (e.g., 'registry.example.com')"
    echo "  REGISTRY_USERNAME     The username for the registry"
    echo "  REGISTRY_PASSWORD     The password for the registry"
    exit 1
}

#
# Check and parse arguments
#

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    print_usage
fi

if [ "$#" -ne 0 ]; then
    echo "Error: Unexpected arguments: $*" >&2
    print_usage
fi

[ -n "$REGISTRY_ENDPOINT" ] || {
    echo "Error: Environment variable 'REGISTRY_ENDPOINT' is not set" >&2
    exit 1
}
echo "Using registry '$REGISTRY_ENDPOINT'"

#
# Setup build env
#

build_path="$(mktemp -d -t metaleg-build-XXXXXX)"
mkdir -p "$build_path/packages"

#
# Create local signing key
#

if ! [ -e "$build_path/melange.rsa" ]; then
    echo "Creating local signing key..."
    melange keygen "$build_path/melange.rsa" || {
        echo "Error: Failed to generate signing key" >&2
        exit 1
    }
fi

#
# Build package
#

echo "Building local package..."

melange build \
    --arch x86_64 \
    --source-dir "$(realpath "$BASE_PATH/..")" \
    --out-dir "$build_path/packages" \
    --cache-dir "$build_path/packages/cache" \
    --signing-key "$build_path/melange.rsa" \
    ./melange.yaml || {
    echo "Error: Failed to build package" >&2
    exit 1
}

#
# Login to registry
#

echo "Logging in to registry..."

export DOCKER_CONFIG="$build_path/.docker"
chmod 700 "$DOCKER_CONFIG"
if [ -n "$REGISTRY_USERNAME" ] && [ -n "$REGISTRY_PASSWORD" ]; then
    echo "$REGISTRY_PASSWORD" | apko login --log-level warn "$REGISTRY_ENDPOINT" --username "$REGISTRY_USERNAME" --password-stdin || {
        echo "Error: Failed to login to registry '$REGISTRY_ENDPOINT' as user '$REGISTRY_USERNAME'" >&2
        exit 1
    }
    echo "Successfully logged in to registry '$REGISTRY_ENDPOINT' as user '$REGISTRY_USERNAME'"
fi

#
# Build images
#

echo "Building and pushing image..."

version_full="$(yq '.package.version + "-r" + .package.epoch // 0' ./melange.yaml)"
version="$(echo "$version_full" | cut -d - -f 1)"
version_1="$(echo "$version" | cut -d . -f 1)"
version_2="$version_1.$(echo "$version" | cut -d . -f 2)"

apko publish \
    --arch x86_64 \
    --cache-dir "$build_path/packages/cache" \
    --sbom=false \
    ./apko.yaml \
    "${REGISTRY_ENDPOINT}/metaleg-agent:${version_full}" \
    "${REGISTRY_ENDPOINT}/metaleg-agent:${version}" \
    "${REGISTRY_ENDPOINT}/metaleg-agent:${version_1}" \
    "${REGISTRY_ENDPOINT}/metaleg-agent:${version_2}" \
    "${REGISTRY_ENDPOINT}/metaleg-agent:latest"
