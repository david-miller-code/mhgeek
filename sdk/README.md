# 本地构建依赖

此目录除本说明外由 `.gitignore` 排除。`runtime/` 保存设备提供的 AInice 头文件与 `libainice.so`；`cjson/`、`curl/`、`openssl/`、`zlib/` 保存匹配目标固件 ABI 的开发头文件及共享库。文件来源、许可和导出方法见根目录 [BUILD.md](../BUILD.md)。不要将账号凭据、设备授权数据、私钥或整个 SDK 目录加入源码提交。
