# 计算机网络相关代码
- sniffer
- arpspoof
- synflood-dos
- endtoend

## sniffer
抓包只使用了socket标准库，自己解析包
### Prerequisites
- Ubuntu (16.04 LTS)
- Python (3.5)
- Django (1.11.7)

### Usage
```
pip3 install django

python3 manage.py makemigrations

python3 manage.py migrate

sudo python3 manage.py runserver

open browser http://127.0.0.0:8000/wshark

```

### Feature
- 抓包，解析（只支持arp，tcp，udp，ftp）(dns，icmp，https只解析了部分)
- 包过滤，协议，端口
- 关键字搜索
- follow tcp stream
- 文件重组（目前只支持http和ftp）

### To Do
- 将django换成qt5
 - 因为网页版有缺陷，不能实时刷新（用ajax也应该能伪造出实时刷新的假象），当包过多时传输会较慢
 - 如果想抓lo网卡，本身会造成干扰
- 完善包的解析
- 界面优化

## arpspoof
用socket构造arp包，进行arp欺骗

（高级路由器可能会有防止arp欺骗的功能，实验可能不成功）
### Prerequisites
- Ubuntu (16.04 LTS)
- Python (3.5)

### can do
- 能让你室友上不了网
- 配合sniffer抓自己手机的包
- 能嗅探你室友的包（他不会有任何知觉）（和上面的原理一样）

### Usage
- 让室友上不了网
 - 先检测局域网下面的存活主机可以用nmap，也可以暴力循环发arp请求包，然后抓包查看回应包，拿到受害target_ip和target_mac
 - 修改sendarp.py 里面的相关ip和mac（为了防止脚本小子，此处不是很详细）
 - `sudo python3 sendarp.py`
- 配合sniffer手机抓包
  - 查看手机的ip和mac，然后修改sendarp.py相应的部分,运行。此时你的手机是上不了网的。
  - `sudo bash arp.sh` 配置iptables实现包转发，让手机能上网。
  - 打开wireshark开始抓包（打开wsniffer可行hhh）
  - 操作完成后`sudo bash recover.sh` 恢复iptables配置
- 嗅探室友的包
  - 操作和上面基本一样，只是将自己手机的ip，mac换成室友的即可
### To Do
- 不单纯转发包，可以先拦下包，修改后再转发，dns挟持，tcp挟持，替换网页内容

## synflood-dos
用socket构造tcp包，设置flag为syn然后发送（可以认为就是个tcp发包器）

### Prerequisites
- Ubuntu (16.04 LTS)
- Python (3.5)

### Usage
- 修改syndos.py里面的source ip 和 destination ip即可,然后`sudo python3 syndos.py`
- `sudo bash rst.sh` 组织本机发送rst包
- 操作完成后`sudo bash recover.sh` 恢复iptables配置

### To Do
- 经测试确实能够占据所有的tcp链接，但是还是能访问网站（在自己的网站进行的测试）原因不明（但是确实能让自己寝室的路由器崩掉，上不了网）

## endtoend
原本想做一个在nat下面的两台主机进行端对端直接通信，后来通过搜索找到了关键词nat traversal，就是nat 打洞。我选择了最简单的udp打洞进行实验，结果由于学校的nat是对称类型的，真正的端到端并没有实现。把我的一些实验代码放到endtoend目录下面。

### To Do
- 继续搞

### nat traversal参考链接
- http://lifeofzjs.com/blog/2014/07/19/how-p2p-in-symmetric-nat/
- http://blog.csdn.net/njupt_t/article/details/51170623
- https://github.com/laike9m/PyPunchP2P
- http://www.bford.info/pub/net/p2pnat/index.html
