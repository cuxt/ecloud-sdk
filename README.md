# ecloud-sdk

> 基于fetch API的天翼网盘SDK，支持在Cloudflare Worker中使用

本项目基于原仓库 [wes-lin/cloud189-sdk](https://github.com/wes-lin/cloud189-sdk) 进行修改，以支持 Cloudflare Worker。

## 使用方法

1. 安装依赖

```sh
npm install ecloud-sdk
```

2. 初始化

```js
const { CloudClient } = require('ecloud-sdk')
// 使用账号密码初始化
const client = new CloudClient({
  username: 'username',
  password: 'password'
})
```

3. 使用

```js
const info = await client.getUserSizeInfo()
console.log(info)
```

## [API 文档](https://cloud.189.whaledev.cn/)
