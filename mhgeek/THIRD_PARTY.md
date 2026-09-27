# 外部依赖与参考项目

MHGeek 自身代码采用仓库根目录 `LICENSE` 中的 GPL-3.0-only 许可；安装包内也包含 `mhgeek/LICENSE`。插件在目标设备上动态使用宿主提供的 `libainice.so`、cJSON、libcurl、OpenSSL 与 zlib；这些库及宿主 SDK 适用其各自的许可，不因本项目的许可而改变。插件包不捆绑这些外部库或 SDK。

中枢交互研究参考 [xiaomi-central-hub-gateway-cli](https://github.com/eyaeya/xiaomi-central-hub-gateway-cli)，未引入该项目的源文件。工作区、发布形式和授权页面参考 [MHCamera](https://github.com/wade-hello/mhcamera)；`www/assets/countries.js` 复用其[同名源文件](https://github.com/wade-hello/mhcamera/blob/main/mhcamera/www/assets/countries.js)，按 MHCamera 的 GPL-3.0-only 许可在本项目中使用。对应 GPLv3 许可全文随插件保存在 `mhgeek/LICENSE`。
