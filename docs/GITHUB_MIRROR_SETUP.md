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

公开仓 `.cnb.yml` 只在确实调用 CNB/GitHub 写入或回读 API 的 stage 通过
`imports` 读取这个密钥文件；下载、解包以及运行时准备阶段都没有密钥。流水线
会先在仓库内创建被 Git 忽略的 `.release-ci-venv`，用完整依赖闭包和
`--require-hashes` 安装签名验证运行时，并按 wheel `RECORD` 再核对实际模块
文件。流水线中的
`scripts/sync_github_release.py` 固定使用官方 `https://api.github.com` API
和目标仓 `ra1nzzz/Dust-Mirror`。它先创建或复用与同一 Product build 绑定的
GitHub 草稿，只补传缺失文件，绝不删除、覆盖或重建已有文件；已有文件和补传
文件都会重复下载并核对大小与 SHA-256。ZIP 上传采用定长分块流，不会把整个
包读入内存；网络中断最多重试三次，并先回读同名远端资产判断上一次请求是否
实际成功。随后草稿只会先转成非 latest 的
prerelease。草稿的 `target_commitish` 必须是签名授权中的 `release_commit`
精确 SHA；回读还会解析 GitHub tag 并核对其 commit 与 tree 同时等于授权中的
`release_commit` / `release_tree`，不能使用会漂移的 `main`。

CNB 的同 tag prerelease 也必须先完成相同的八文件验收。只有两端都处于已验证
的非 latest 状态后，`scripts/promote_public_release.py` 才进入最终提升：先提升
CNB，再提升 GitHub；GitHub 提升失败会立即把 CNB 恢复为非 latest。进程在两步
之间被中断时，下一次同 Product build 调用会先修复断点再继续，不会删除、重建
Release，也不会接受同名异字节资产。最终阶段会再次回读两端 latest 与完整资产。

因此：

- 不需要为观尘 GUI 配置任何公网页面地址；
- 不需要生成新的“协调服务公钥”；
- 不需要第二套发布签名私钥；
- GitHub Token 只用于发布仓写入；CNB Token 还需具备公开 CNB 发布仓的
  `repo-release:rw`，用于可补偿的 latest/non-latest 状态切换。

仓库分叉、历史发布实验及本发布仓双端 ancestry 的收敛记录统一保存在
[Dev 项目知识库](https://github.com/ra1nzzz/DustMirror-Dev/blob/master/docs/99-%E5%BD%92%E6%A1%A3/%E4%BB%93%E5%BA%93%E6%B2%BB%E7%90%86/BRANCH_CONSOLIDATION_2026-08-14.md)。
本仓不另建第二份项目状态或分支台账。
