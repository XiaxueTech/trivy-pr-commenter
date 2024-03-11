#!/usr/bin/env bash

set -xe

if [ -z "${INPUT_GITHUB_TOKEN}" ] ; then
  echo "Consider setting a GITHUB_TOKEN to prevent GitHub api rate limits." >&2
fi

ls -la

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

  curl -sLo "${binary}" "$(echo "${release_assets}" | jq -r ". | select(.name == \"${binary}\") | .download_url")"
  curl -sLo "$3-checksums.txt" "$(echo "${release_assets}" | jq -r ". | select(.name | contains(\"$checksum\")) | .download_url")"

  grep "${binary}" "$3-checksums.txt" | sha256sum -c -
  install "${binary}" "/usr/local/bin/${3}"
}

install_release radugrecu/trivy-terraform-pr-commenter "/latest" trivy-terraform-pr-commenter checksums.txt

ls -l /usr/local/bin/
trivy-terraform-pr-commenter ${INPUT_REPORT_FILE}