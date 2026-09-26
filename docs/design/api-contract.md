# eota API 合同

`eota_` 是第一方机制 API；`esp_ota_*` 仍属于 ESP-IDF。库不消费网络命令中的 target 作为信任来源，产品约束必须由受控应用装配。`eota_policy_t` 指定非空项目名、芯片 ID、两个 OTA 槽的地址与共同大小、下载期限及已建立可信时间的事实。应用先用 `eota_available` 拒绝普通未签名构建。本组件在 IDF 目标上编译拒绝 `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`，避免 SDK 的 pending 确认入口写 eFuse。

1. 应用核对请求授权、当前业务状态、网络与可信时间；用 `eota_preflight(policy, size, slots)` 核对可写安全条件并取得真实运行/目标槽、大小和状态。`eota_observe_slots` 是只读事实接口，即使 boot selector 与运行槽不一致也报告实际槽和镜像状态，供跨启动结果查询。应用在首次目标槽写入前持久提交操作收据并精确读回。
   联合 Container 固件切换还需先完成旧备用固件退役：应用在同一个存储 owner 下，以已读回的持久收据和当前 ECS2 绑定授权 `eota_retire_inactive`，传入精确目标 subtype 与已确认运行镜像 SHA。库核对当前运行/选中槽 VALID、运行镜像产品约束与完整签名摘要，确保目标首个扇区已擦除并读回 `0xff` 镜像魔数，再尝试使备用 otadata 失效；只有重新观察到目标镜像验签无效、目标 otadata 不处于可启动状态且运行镜像仍精确匹配时才返回成功。应用随后才可把 Container 中已证明不可启动的旧备用绑定退役，并执行 `eota_prepare`。任一失败或重启必须依据原收据和实际镜像/otadata/ECS2 状态继续对账，不能把本 API 的一次失败当成未写入。仅凭 app 侧签名校验失败不能证明 bootloader 不会回退装载；物理镜像魔数读回是独立必要条件。
2. 应用在唯一专用 worker 调用 `eota_prepare`。URL 只接受 HTTPS；HTTP 必须是 200、确定且一致的 Content-Length、非 chunked、不重定向。镜像头项目、芯片和 SDK 有效性核对后才调用 `esp_ota_begin`。完整 signed bin 写入后从目标槽读回，核对 SHA-256，再由 `esp_ota_end` 验签。返回 `eota_prepared_t` 时 boot selector 仍指向原槽；固定 IDF 的 `esp_ota_begin` 会尝试使 inactive 槽原有的 otadata 记录失效，准备阶段并非 otadata 全程不变。
3. 应用持久提交与业务包的兼容绑定，再调用 `eota_select`。它重新核对运行/目标槽、目标整镜像摘要，并从目标 Flash 读回镜像头，按本次传入的可信 policy 重验项目名、芯片及 SDK 镜像头约束，然后调用 SDK 的 `esp_ota_set_boot_partition` 再验签。先前的 `prepare` 结果不能豁免当前产品约束。选择读回与可回退事实不成立时尝试恢复旧槽；SDK 恢复选择会把旧槽标成 NEW，所以还要将实际运行槽恢复为 VALID，清除未启动候选的 NEW 记录，并读回安全预检条件。任一步读回不明明确返回 `EOTA_UPDATE_BOOT_STATE_UNKNOWN`，应用不得自动重启。
4. 应用决定重启。新启动的本地自检及稳定窗口通过后才调用 `eota_confirm_pending`；已确认的 VALID 状态可幂等返回，UNTRACKED 不代表确认成功。明确失败时调用 `eota_reject_pending`，该 SDK 调用可能直接重启。`eota_inspect` 和 `eota_sha256_running` 让应用把持久收据与当前实际运行镜像关联，最终业务结果由应用裁决。

`eota_sha256_verified_image` 是只读镜像身份接口：只接受 policy 精确声明的 `ota_0`／`ota_1` 物理分区，先经固定 SDK 的 `esp_image_verify(ESP_IMAGE_VERIFY)` 验证完整镜像及签名，再按返回的 `image_len` 对包括签名块的整份 signed bin 计算 SHA-256。它不从 `esp_partition_get_sha256` 取应用附加摘要，因为该值不覆盖签名块；也不把“镜像验签通过”等同于 otadata 允许启动、选中运行、可回退、属于当前产品或通过业务自检。失败时有效输出清零。Base 如需生成 Container 的固件集合，必须在同一串行所有权下读取真实 boot selector、两个 OTA 状态和已验签镜像；`NEW` 只是未启动候选，`PENDING_VERIFY` 下次启动会被 bootloader 标成 `ABORTED`，两者均不能仅凭分区存在就宣称已确认可启动。当前 Base 没有独立包分区与联合 OTA 状态机，不能将此接口的返回值直接填入 `econtainer_slot_firmware_set_t`。

`eota_prepare` 产出收据前、`eota_select` 写入 boot selector 前，以及 `eota_sha256_running` 为持久收据查询计算摘要前，都通过 `esp_image_verify(ESP_IMAGE_VERIFY)` 取得已验签的 `image_len`，要求它与请求或收据长度精确相等；不接受只覆盖前缀的摘要或附加尾缀。固定 SDK 的 `esp_ota_end`／`esp_ota_set_boot_partition` 按整个分区验签，并不将写入长度与完整签名长度比较；`esp_ota_begin` 又只擦除请求长度向上取整的范围，短请求可能留下仍然有效的旧签名扇区。该检查绑定的是完整镜像身份，不改变 SDK 签名信任来源。`esp_image_get_metadata` 的长度不含签名，不能替代已验签的长度。保留原 OTA 结束／选择验签会增加一次 SDK 验签成本；准备阶段仍在额外验签返回后检查同一下载期限，逾期不产出收据。

调用方在同步操作期间持有 URL、policy、进度上下文与唯一 worker，不并发释放或重复写槽。进度回调只在 `eota_prepare` 调用栈内使用，不能重入 `eota_` 或阻塞业务。产品操作 ID、同 ID 去重、NVS 命名空间、配置事务、USB/MQTT/FRP 协议、Container 包槽均不进入本库。

IDF v6.1 的 HTTP header、发送与响应体方法都可能在单次调用内多次使用底层传输，不能只给每次调用设置相同的 socket 超时。本仓只保留一个网络路径：官方 `esp_http_client` 负责 HTTP 状态与解析，自有 custom transport 先通过 lwIP 核心线程的异步 DNS API 解析，再以非阻塞 socket 连接，并用 mBed TLS 公共 API 执行 TLS。`CONFIG_ESP_HTTP_CLIENT_ENABLE_CUSTOM_TRANSPORT=y` 是签名 OTA 必需配置。TLS 强制 `VERIFY_REQUIRED`、CA bundle 与原 URL 主机名的 SNI/证书名验证；HTTP 客户端保留原 URL 和 Host。

总期限从 `eota_prepare` 的槽预检前开始；无进展期限由 DNS 解析完成、TCP 连接完成及实际收发的网络字节刷新；DNS、TCP、TLS、请求发送、响应头和响应体共用这两项绝对期限，连接阶段另受 `connect_timeout_ms` 约束。单调时钟是唯一的期限事实，不创建到期定时器；DNS 每 tick 检查一次。单次 TLS 读写以 SDK 传入的 `read_timeout_ms` 建立绝对截止；该截止覆盖同一 TLS 记录的多次非阻塞收发，也覆盖 TLS 1.3 连续返回会话票据而尚未交付应用数据的循环，`select` 等待取它与总期限、无进展期限的最短剩余时间。进展必须先通过旧期限检查，逾期结果或字节不能续期；单次 TLS 密码学步骤若恰在读写截止后产出明文，传输先交还已消费的数据，以免丢失记录，并在下一步重新检查总期限。DNS 迟到回调由独立引用持有上下文，至多保留一个未完成解析。HTTP 返回后由同步调用方清理 client，再销毁 custom transport 并关闭 socket。

这些期限约束正常调度下的网络等待和每次调用的返回边界。准备阶段在 `esp_ota_begin/write/end`、分区读回和 HTTP 清理返回后继续检查下载期限；逾期不产出 `eota_prepared_t`，调用方不得切槽。固定 lwIP 的 `socket`/`close` 可能同步等待 TCP/IP 线程；mBed TLS 单次密码学步骤、已缓存记录解析、HTTP 解析、Flash 操作及验签不能被本库抢占。库因此不承诺 30 秒无进展或 5 分钟总期限就是 `eota_prepare` 的严格墙钟返回上界。真实 HTTPS 的 CA、SNI、证书名与长期慢滴流尚无实板运行证据；主计划 P5-04 仍未验收。
