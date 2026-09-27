#!/usr/bin/env bash
# Builds the standalone ARM64 MHGeek plugin backend (`mhgeek.app`).
#
# The final link imports host SDK symbols from libainice.so.
# Local SDK and third-party development files remain outside the repository.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUT="${1:-${MHGEEK_BACKEND_OUT:-$PROJECT_ROOT/build/mhgeek.app}}"
TOOLCHAIN_PREFIX="${MHGEEK_TOOLCHAIN_PREFIX:-$PROJECT_ROOT/toolchains/arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-}"
CC="${MHGEEK_BACKEND_CC:-${TOOLCHAIN_PREFIX}gcc}"
STRIP="${MHGEEK_BACKEND_STRIP:-${TOOLCHAIN_PREFIX}strip}"
READELF="${MHGEEK_BACKEND_READELF:-${TOOLCHAIN_PREFIX}readelf}"
SUBSYS_RUNTIME_DIR="${MHGEEK_SDK_ROOT:-$PROJECT_ROOT/sdk/runtime}"
MHG_SRC_DIR="$PROJECT_ROOT/mhgeek/src"
COMMON_SUPPORT_DIR="$MHG_SRC_DIR/support"
SUBSYS_CJSON_ROOT="${MHGEEK_CJSON_ROOT:-$PROJECT_ROOT/sdk/cjson}"
SUBSYS_CURL_ROOT="${MHGEEK_CURL_ROOT:-$PROJECT_ROOT/sdk/curl}"
SUBSYS_OPENSSL_ROOT="${MHGEEK_OPENSSL_ROOT:-$PROJECT_ROOT/sdk/openssl}"
SUBSYS_ZLIB_ROOT="${MHGEEK_ZLIB_ROOT:-$PROJECT_ROOT/sdk/zlib}"

die() { echo "error: $*" >&2; exit 1; }

[ -x "$CC" ] || die "compiler missing: $CC"
[ -x "$STRIP" ] || die "strip missing: $STRIP"
[ -f "$MHG_SRC_DIR/app/main.c" ] || die "mhgeek app source missing: $MHG_SRC_DIR/app/main.c"
[ -f "$MHG_SRC_DIR/runtime.c" ] || die "mhgeek runtime source missing: $MHG_SRC_DIR/runtime.c"
[ -f "$COMMON_SUPPORT_DIR/json_strict.c" ] || die "plugin support source missing: $COMMON_SUPPORT_DIR/json_strict.c"
[ -f "$SUBSYS_RUNTIME_DIR/usr/include/ainice/bridge.h" ] || die "host SDK bridge header missing: $SUBSYS_RUNTIME_DIR/usr/include/ainice/bridge.h"
[ -f "$SUBSYS_RUNTIME_DIR/usr/include/ainice/event.h" ] || die "host SDK event header missing: $SUBSYS_RUNTIME_DIR/usr/include/ainice/event.h"
[ -f "$SUBSYS_RUNTIME_DIR/usr/include/ainice/device.h" ] || die "host SDK device header missing: $SUBSYS_RUNTIME_DIR/usr/include/ainice/device.h"
[ -e "$SUBSYS_RUNTIME_DIR/usr/lib/libainice.so" ] || die "host SDK libainice missing: $SUBSYS_RUNTIME_DIR/usr/lib/libainice.so"
[ -f "$SUBSYS_CURL_ROOT/include/curl/curl.h" ] || die "libcurl headers missing: $SUBSYS_CURL_ROOT"
[ -e "$SUBSYS_CURL_ROOT/lib/libcurl.so" ] || [ -e "$SUBSYS_CURL_ROOT/lib/libcurl.so.4" ] || die "libcurl runtime missing: $SUBSYS_CURL_ROOT"
[ -f "$SUBSYS_OPENSSL_ROOT/include/openssl/sha.h" ] || die "OpenSSL headers missing: $SUBSYS_OPENSSL_ROOT"
[ -f "$SUBSYS_CJSON_ROOT/include/cjson/cJSON.h" ] || die "cJSON headers missing: $SUBSYS_CJSON_ROOT"

mkdir -p "$(dirname "$OUT")"
"$CC" -std=c11 -O2 -g0 -Wall -Wextra -Werror -Wpedantic \
  -DOPENSSL_SUPPRESS_DEPRECATED \
  -ffile-prefix-map="$PROJECT_ROOT"=. \
  -fmacro-prefix-map="$PROJECT_ROOT"=. \
  -DMHG_APP_CA_INFO="\"/etc/ssl/certs/ca-certificates.crt\"" \
  -I"$SUBSYS_RUNTIME_DIR/usr/include" \
  -I"$MHG_SRC_DIR" -I"$MHG_SRC_DIR/app" \
  -I"$COMMON_SUPPORT_DIR" \
  -I"$SUBSYS_CJSON_ROOT/include" \
  -I"$SUBSYS_CURL_ROOT/include" \
  -I"$SUBSYS_OPENSSL_ROOT/include" \
  -I"$SUBSYS_ZLIB_ROOT/include" \
  "$MHG_SRC_DIR/app/main.c" "$MHG_SRC_DIR/app/operations.c" "$MHG_SRC_DIR/app/bridge.c" \
  "$MHG_SRC_DIR/app/routes.c" "$MHG_SRC_DIR/app/json.c" \
  "$MHG_SRC_DIR/runtime.c" "$MHG_SRC_DIR/presence_source.c" \
  "$MHG_SRC_DIR/presence_delivery.c" "$MHG_SRC_DIR/lan_driver.c" \
  "$MHG_SRC_DIR/lan_owner.c" "$MHG_SRC_DIR/transport.c" \
  "$MHG_SRC_DIR/session.c" "$MHG_SRC_DIR/channel.c" "$MHG_SRC_DIR/jpake.c" \
  "$MHG_SRC_DIR/resource_graph.c" "$MHG_SRC_DIR/resource_lan.c" "$MHG_SRC_DIR/resource_sync.c" \
  "$MHG_SRC_DIR/resource_store.c" "$MHG_SRC_DIR/spec_action.c" \
  "$MHG_SRC_DIR/board_identity.c" \
  "$MHG_SRC_DIR/emit_lan.c" \
  "$MHG_SRC_DIR/event_config_store.c" \
  "$COMMON_SUPPORT_DIR/atomic_file.c" \
  "$MHG_SRC_DIR/target_resolver.c" "$MHG_SRC_DIR/target_store.c" \
  "$MHG_SRC_DIR/xiaomiio_catalog.c" "$MHG_SRC_DIR/core_bootstrap.c" \
  "$MHG_SRC_DIR/xiaomi_session.c" "$MHG_SRC_DIR/xiaomi_service.c" \
  "$MHG_SRC_DIR/xiaomi_account_url.c" "$MHG_SRC_DIR/mijia_core.c" \
  "$MHG_SRC_DIR/cloud_http.c" "$MHG_SRC_DIR/cloud_crypto.c" \
  "$MHG_SRC_DIR/https_client.c" "$MHG_SRC_DIR/rc4_drop1024.c" \
  "$MHG_SRC_DIR/wire_scalar.c" "$MHG_SRC_DIR/secret_json.c" \
  "$MHG_SRC_DIR/auth_sms.c" "$MHG_SRC_DIR/auth_sms_http.c" \
  "$MHG_SRC_DIR/auth_sms_executor.c" "$MHG_SRC_DIR/auth_sms_adapter.c" \
  "$MHG_SRC_DIR/auth_sms_file_store.c" "$MHG_SRC_DIR/account_store.c" \
  "$MHG_SRC_DIR/passport_wire.c" "$MHG_SRC_DIR/passport_device_id.c" \
  "$MHG_SRC_DIR/common.c" "$MHG_SRC_DIR/cloud_wire_types.c" \
  "$COMMON_SUPPORT_DIR/json_strict.c" \
  -L"$SUBSYS_RUNTIME_DIR/usr/lib" \
  -L"$SUBSYS_CJSON_ROOT/lib" \
  -L"$SUBSYS_CURL_ROOT/lib" \
  -L"$SUBSYS_OPENSSL_ROOT/lib" \
  -L"$SUBSYS_ZLIB_ROOT/lib" \
  -Wl,-rpath-link,"$SUBSYS_RUNTIME_DIR/usr/lib" \
  -Wl,-rpath-link,"$SUBSYS_CJSON_ROOT/lib" \
  -Wl,-rpath-link,"$SUBSYS_CURL_ROOT/lib" \
  -Wl,-rpath-link,"$SUBSYS_OPENSSL_ROOT/lib" \
  -Wl,-rpath-link,"$SUBSYS_ZLIB_ROOT/lib" \
  -Wl,--as-needed -Wl,--no-allow-shlib-undefined -Wl,-z,defs \
  -lainice -lcjson -lcurl -lssl -lcrypto -lz -lm -pthread \
  -o "$OUT"
for symbol in ainice_bridge_response_json ainice_bridge_serve_until ainice_device_wifi_mac_hex ainice_presence_subscribe_until; do
  "$READELF" -W -s "$OUT" | awk -v symbol="$symbol" '$7 == "UND" && ($8 == symbol || index($8, symbol "@") == 1) { found=1 } END { exit found ? 0 : 1 }' ||
    die "mhgeek must import $symbol from libainice.so"
  ! "$READELF" -W -s "$OUT" | awk -v symbol="$symbol" '$7 != "UND" && ($8 == symbol || index($8, symbol "@") == 1) { found=1 } END { exit found ? 0 : 1 }' ||
    die "mhgeek must not define SDK symbol: $symbol"
done
"$READELF" -W -s "$OUT" | awk '$5 != "LOCAL" && $7 != "UND" && $8 ~ /^ainice_/ { found=1 } END { exit found ? 0 : 1 }' &&
  die "mhgeek must not define any runtime SDK symbol"
"$READELF" -d "$OUT" | awk '$2 == "(NEEDED)" && $5 == "[libainice.so]" { found=1 } END { exit found ? 0 : 1 }' ||
  die "mhgeek NEEDED set must include libainice.so"
"$STRIP" --strip-all "$OUT"
chmod 0755 "$OUT"
echo "$OUT"
