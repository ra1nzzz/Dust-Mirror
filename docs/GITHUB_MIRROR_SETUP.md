# GitHub 发布镜像配置

观尘是本地 GUI 程序，不需要“发布协调服务地址”，也不需要把协调服务的
Token 或公钥放进客户端。CNB 是主发布仓，公开仓只负责把 CNB 已验证的八个
制品同步到 GitHub Release。

## 唯一新增凭证：`GITHUB_TOKEN`

在 GitHub 生成一个 Fine-grained personal access token，资源所有者选
`ra1nzzz`，Repository access 只选 `ra1nzzz/Dust-Mirror`，权限只需要：

- Contents: Read and write
- Metadata: Read（GitHub 会自动要求，不能关闭）

不要授予 Actions、Administration、Pull requests、Secrets 或组织级权限。

把 Token 作为密钥写入 CNB 的私有密钥仓
`yitaocn/dustmirror-release-secrets` 的 `env.release.yml`：

```yaml
allow_slugs: "yitaocn/dust-mirror"
allow_events: "api_trigger_publish_windows_release"
GITHUB_TOKEN: "<只在CNB密钥仓保存，不要提交到代码仓>"
```

文件中原有的 `CNB_TOKEN`、`DUSTMIRROR_*_PUBLIC_KEY_B64` 等发布门禁变量继续
保留；本次不新增 `DUSTMIRROR_RELEASE_COORDINATOR_ORIGIN`、
`DUSTMIRROR_RELEASE_COORDINATOR_TOKEN` 或
`DUSTMIRROR_RELEASE_COORDINATOR_PUBLIC_KEY_B64`。

公开仓 `.cnb.yml` 通过 `imports` 读取这个密钥文件。流水线中的
`scripts/sync_github_release.py` 固定使用官方 `https://api.github.com` API
和目标仓 `ra1nzzz/Dust-Mirror`，先以草稿/预发布状态创建或复用 Release，上传
恰好八个已授权文件，逐个回下载并重算 SHA-256，全部一致后才设置为 latest。

因此：

- 不需要为观尘 GUI 配置任何公网页面地址；
- 不需要生成新的“协调服务公钥”；
- 不需要第二套发布签名私钥；
- GitHub Token 只用于发布仓写入，CNB Token 只用于 CNB 主仓的既有门禁。
