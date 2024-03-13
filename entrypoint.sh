#!/usr/bin/env bash

set -xe

if [ -z "${INPUT_GITHUB_TOKEN}" ]; then
  echo "Consider setting a GITHUB_TOKEN to prevent GitHub API rate limits." >&2
  exit 1
fi

function get_release_assets {
  repo="$1"
  version="$2"
  args=(
    -sSL
    --header "Accept: application/vnd.github+json"
  )
  [ -n "${INPUT_GITHUB_TOKEN}" ] && args+=(--header "Authorization: Bearer ${INPUT_GITHUB_TOKEN}")
  curl "${args[@]}" "https://api.github.com/repos/$repo/releases${version}" |
    jq '.assets[] | { name: .name, download_url: .browser_download_url }'
}

function install_release {
  repo="$1"
  version="$2"
  binary="$3-linux-amd64"
  checksum="$4"
  release_assets="$(get_release_assets "${repo}" "${version}")"

  binary_url=$(echo "${release_assets}" | jq -r ". | select(.name == \"${binary}\") | .download_url")
  if [ -z "$binary_url" ]; then
    echo "Error: Failed to retrieve download URL for ${binary}."
    exit 1
  fi

  curl -sLo "${binary}" "$binary_url"
  curl -sLo "$3-checksums.txt" "$(echo "${release_assets}" | jq -r ". | select(.name | contains(\"$checksum\")) | .download_url")"

  grep "${binary}" "$3-checksums.txt" | sha256sum -c -
  install "${binary}" "/usr/local/bin/${3}"
  rm "${binary}" "$3-checksums.txt"
}

install_release XiaxueTech/trivy-terraform-pr-commenter "/latest" trivy-terraform-pr-commenter checksums.txt

ls -l /usr/local/bin/

if ! trivy-terraform-pr-commenter "${INPUT_REPORT_FILE}"; then
  echo "Error: Failed to execute Trivy PR commenter."
  exit 1
fi
