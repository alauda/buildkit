# buildkit 变更记录

官方地址：[buildkit](https://github.com/moby/buildkit/tree/v0.10.4)

## 漏洞修复

- [DEVOPS-19214](https://jira.alauda.cn/browse/DEVOPS-19214)替换了构建镜像的基础镜像 alpine目录构建需要的基础镜像。官方使用的基础镜像构建：https://github.com/tonistiigi/dockerfile-alpine
  - https://gitlab-ce.alauda.cn/devops/builder-buildkit/-/merge_requests/3
  - https://gitlab-ce.alauda.cn/devops/builder-buildkit/-/tree/alpine-3.16/alpine


## 添加 Insecure 仓库自动识别

- [DEVOPS-19463](https://jira.alauda.cn/browse/DEVOPS-19463) pull http仓库失败问题
- [DEVOPS-19601](https://jira.alauda.cn/browse/DEVOPS-19601) 连接自签名https仓库拉取失败问题
  - https://gitlab-ce.alauda.cn/devops/builder-buildkit/-/merge_requests/4

## 修复 walk 路径时可能存在的异常空

- https://github.com/tonistiigi/fsutil/pull/120 

## 调整 daemonless 脚本默认重试次数

将 BUILDCTL_CONNECT_RETRIES_MAX 改为30，官方默认为10。

## 修复依赖漏洞

将 golang.org/x/net 升级为 v0.7.0, 其他依赖跟随变动。

- https://gitlab-ce.alauda.cn/devops/builder-buildkit/-/merge_requests/12

## 升级 runc 版本

为了修复应用漏洞，升级 runc 版本: v1.0.2 -> v1.1.9

## 修复漏洞升级构建依赖包

github.com/docker/distribution v2.8.1 => v2.8.2-beta.1
github.com/opencontainers/runc v1.1.2 => v1.1.6
golang.org/x/net v0.7.0 => v0.8.0
