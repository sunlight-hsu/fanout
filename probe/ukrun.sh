#!/usr/bin/env bash
# ukrun.sh — 包一层 `unikraft run`：UKC_DOMAIN 非空时先带 --domain 运行，
# 失败则去掉旗标用自动子域名重试。其余参数原样透传。
set -u
if [ -n "${UKC_DOMAIN:-}" ]; then
  if unikraft run --domain "$UKC_DOMAIN" "$@"; then
    exit 0
  fi
  echo "::warning::--domain $UKC_DOMAIN 运行失败，回退自动子域名重试" >&2
fi
exec unikraft run "$@"
