```
0                   1                   2                   3   
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
# 运行方式
- cd wsniff
- python3 manage.py makemigrations wshark
- python3 manage.py migrate
- sudo python3 manage.py runserver
- 可能需要更改wsniff/wsniffer.py 里面的网卡名称


# 抓包流程
- 访问127.0.0.1/wshark
- 开始抓包127.0.0.1/wshark?start=on
- 停止抓包127.0.0.1/wshark?start=off
- 如果不是通过start=off,关闭可能会出现start=on 时候不能开启, 此时需要清除session, 127.0.0.1/wshark?start=clear, 然后再执行shtart=on
- 删除所有抓的包 127.0.0.1/wshark?delete=yes
- 傻瓜式 follow stream index , 在首页直接点击一行,然后点击链接follow stream(没有考虑out of order)
- 文件下载 http://127.0.0.1:8000/wshark/stream/38474?import (没有把图片text/html分开,直接以二进制文件存储)

已解决:
- 抓包
- 解析包()
- 查询
- 重组

待解决:
- models需增加 icmp 和dns
- 解决out of oreder问题
-  tcp dup 问题
- 包过滤
- 数据包保存
- 文件过滤 可能根据http 请求头的content-type , text/html,.....等类型
-
wireshark 根据srcip port desip port 来确认是同一流(stream index)

ip_header 代表的是32-bits word的数量
tcp_header 也一样 tcpheader 也叫做 dataoffset ,就是actual data 的位置

tcp_segment_len = total - ip_header - tcp_header

#http://networkstatic.net/what-are-ethernet-ip-and-tcp-headers-in-wireshark-captures/
根据5元组来确定 stream index
#https://blog.packet-foo.com/2015/03/tcp-analysis-and-the-five-tuple/

about squence number
http://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/

#bug
- 解析dns 回复的包的时候会有问题
- 可能会丢失最后100个包(解决方法, 尽量抓时间长一点,多抓一点包)
