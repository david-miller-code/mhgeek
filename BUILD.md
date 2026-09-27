# 独立构建与打包

开发主机为 Linux x86_64；目标为 A53 / AArch64、glibc 2.38 的 AInice视觉空间传感器。板端不需要编译器。项目代码编译成插件自己的 `mhgeek.app`，运行时调用设备提供的 `libainice.so`，不会把宿主 SDK 链入源码仓库。

## 目录与依赖

```text
mhgeek/
  README.md  BUILD.md  LICENSE
  mhgeek/           插件源码、Web 页面、plugin.json、第三方说明
  scripts/          板端 SDK 导出、构建、打包
  sdk/              本地编译依赖，不提交
  toolchains/       Arm GNU Toolchain，不提交
  build/            构建输出，不提交
  releases/         本地安装包与校验，不提交
```

需要 Bash、Python 3、OpenSSH、curl、tar、sha256sum，以及 Arm GNU Toolchain **13.2.Rel1 / aarch64-none-linux-gnu**。工具链完整解压到 `toolchains/arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-linux-gnu/`；使用其 glibc 2.38 sysroot。也可设置 `MHGEEK_TOOLCHAIN_PREFIX` 指向同目标的编译工具前缀，例如 `/path/bin/aarch64-none-linux-gnu-`。

交叉编译需要以下头文件及共享库；这些是**本地依赖**，不进入 Git 仓库：

| 变量 | 默认目录 | 必需内容 |
| --- | --- | --- |
| `MHGEEK_SDK_ROOT` | `sdk/runtime` | `usr/include/ainice/`、`usr/lib/libainice.so` |
| `MHGEEK_CJSON_ROOT` | `sdk/cjson` | `include/cjson/cJSON.h`、`lib/libcjson.so` |
| `MHGEEK_CURL_ROOT` | `sdk/curl` | `include/curl/`、`lib/libcurl.so` |
| `MHGEEK_OPENSSL_ROOT` | `sdk/openssl` | `include/openssl/`、`lib/libssl.so`、`lib/libcrypto.so` |
| `MHGEEK_ZLIB_ROOT` | `sdk/zlib` | `include/zlib.h`、`lib/libz.so` |

各依赖必须与目标固件架构和 ABI 匹配。不要把开发主机的 x86_64 库放进这些目录。构建脚本不下载未锁定版本的依赖，也不把上述库捆绑进插件包。

## 从自己的设备导出宿主 SDK

普通设备账号通常可读取 `/usr/include/ainice/` 和 `/usr/lib/libainice.so`。设置地址后执行：

```bash
export BOARD_HOST='你的设备地址'
bash scripts/export_device_sdk.sh
```

SSH 密码由 OpenSSH 交互询问，脚本不保存账号密码。导出脚本还读取设备的 cJSON 共享库，下载校验过的同版 cJSON 头文件。其他依赖请从与目标固件对应的开发环境准备到上表目录。SDK 和第三方库的再分发遵守各自条款。

## 构建与打包

```bash
bash scripts/build_backend.sh
python3 scripts/package_plugin.py
```

默认编译输出为 `build/mhgeek.app`。打包脚本将仓库根目录的 `LICENSE` 放入插件包，生成 `releases/mhgeek-<version>.plugin` 及其 SHA-256 校验文件；可用 `--backend`、`--output-dir` 指定路径。安装包体积上限为 64 MiB，打包前拒绝 PEM 私钥内容。

发布安装包时，应同时提供与该包对应版本的完整项目源码和构建脚本，例如公开相应 Git 标签，并在下载页面明确给出源码获取位置。
