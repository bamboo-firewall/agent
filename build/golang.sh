#!/usr/bin/env bash

readonly SUPPORTED_PLATFORMS=(
  linux/amd64
  linux/arm64
)

golang::build_binaries() {
  local host_platform
  host_platform=$(golang::host_platform)
  local found=false
  for platform in "${SUPPORTED_PLATFORMS[@]}"; do
    if [[ "${platform}" == "${host_platform}" ]]; then
      found=true
      break
    fi
  done
  if [[ "${found}" == true ]]; then
    golang::build_binary_for_platform ${platform} $1 $2
  else
    echo "Not support ${host_platform} platform"
  fi
}

golang::build_binary_for_platform() {
  local platform="$1"
  local build_dir="$2"
  local bin_name="$3"

  GOOS=${platform%%/*}
  GOARCH=${platform##*/}
  output="${BUILD_CMD_PATH}/${GOOS}/${GOARCH}/${bin_name}"

  CGO_ENABLED=${CGO_ENABLED} GOOS=${GOOS} GOARCH=${GOARCH} ${GO_BUILD} -ldflags="${LDFLAGS}" -o ${output} ${build_dir}
}

golang::host_platform() {
  echo "$(go env GOHOSTOS)/$(go env GOHOSTARCH)"
}
