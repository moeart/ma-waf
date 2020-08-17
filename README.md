# MA-WAF 萌绘WAF

## 萌绘WAF额外说明文档

* 先按下面的安装说明进行安装
* 从 /config.lua.sample 拷贝到 /config.lua
* 修改 config.lua 配置文件
* 从 /rules/sample 拷贝规则样本到 /rules
* 修改规则文件
* 重启 nginx 完成安装
* 更新规则库直接 git pull

本版本由萌绘图站开发组进行维护，禁止转卖。    
如需从本版本二次开发，请在 README 中注明出处！


## 关于 MA-WAF

MA-WAF是一款适用中、小企业的云WAF系统，让中、小企业也可以非常方便地拥有自己的免费云WAF。

# 主要特性

- 支持对常见WEB攻击的防御，如sql注入、xss、路径穿越，阻断扫描器的扫描等
- 对持对CC攻击的防御
- waf为反向模式，后端保护的服务器可直接用内网IP，不需暴露在公网中
- 支持IP、URL、Referer、User-Agent、Get、Post、Cookies参数型的防御策略
- 安装、部署与维护非常简单
- 支持在线管理waf规则
- 支持在线管理后端服务器
- 多台waf的配置可自动同步
- 跨平台，支持在linux、unix、mac和windows操作系统中部署


# 下载安装
## waf安装
### centos平台

从[openresty](http://openresty.org/en/download.html)官方下载最新版本的源码包。

编译安装openresty：

```bash
yum -y install pcre pcre-devel
wget https://openresty.org/download/openresty-1.9.15.1.tar.gz
tar -zxvf openresty-1.9.15.1.tar.gz 
cd openresty-1.9.15.1
./configure 
gmake && gmake install

/usr/local/openresty/nginx/sbin/nginx  -t
nginx: the configuration file /usr/local/openresty/nginx/conf/nginx.conf syntax is ok
nginx: configuration file /usr/local/openresty/nginx/conf/nginx.conf test is successful
/usr/local/openresty/nginx/sbin/nginx 
```

### ubuntu平台安装

编译安装openresty：

```bash
apt-get install libreadline-dev libncurses5-dev libpcre3-dev libssl-dev perl make build-essential
sudo ln -s /sbin/ldconfig /usr/bin/ldconfig
wget https://openresty.org/download/openresty-1.9.15.1.tar.gz
tar -zxvf openresty-1.9.15.1.tar.gz
cd openresty-1.9.15.1
make && sudo make install
```

### 致谢

1. 感谢春哥开源的[openresty](https://openresty.org)
1. 感谢unixhot开源的[waf](https://github.com/unixhot/waf)
1. 感谢无闻开源的[macron](https://go-macaron.com/)和[peach](https://peachdocs.org/)
1. 感谢lunny开源的[xorm](https://github.com/go-xorm/xorm)
1. 感谢小米安全团队开源的[x-waf](https://waf.xsec.io/)
1. 感谢hamishforbes开源的[iputils](https://github.com/hamishforbes/lua-resty-iputils)
