# frpc-command-mgr

---

## 开发状态
目前正在开荒，欢迎大家的参与！  
接受PR  
（作者是一名初二的学生，水平有限，欢迎大家多多指教）

## 说明
frpc-command-mgr是一个frpc命令管理工具，可以让你的frp客户端像ngrok一样简单，不需要对frp复杂的配置文件耗费精力。

## 使用
`fcm addserver`:添加一个frps服务端 

    fcm addserver                  进入交互式添加服务端流程
    fcm addserver <ip, domain> [options]  
        -p, --bind-port <port>     frp服务端绑定端口，默认7000
        -t, --token <token>        frp服务端token，默认空
        -n, --name <name>          frp服务端名称，默认服务端ip或域名
        -u, --user <user>          frp服务端标识用户名，默认当前机器名称
        --set-default              设置为默认服务端，创建隧道时默认使用该服务端

`fcm addtunnel`:添加一个穿透隧道

    fcm addtunnel                  进入交互式添加隧道流程
    fcm addtunnel <local_port> [options]
    fcm addtunnel <local_port> <remote_port> [options]
    fcm addtunnel <local_ip:local_port> [options]
    fcm addtunnel <local_ip:local_port> <remote_port> [options]
        -r, --remote-name <name>   远程服务端名称，默认为默认服务端  
        -p, --protocol <protocol>  协议类型，可选tcp/udp，默认tcp
        -n, --name <name>          隧道名称，默认空

`fcm mossfrp`:快速使用mossfrp穿透码创建隧道，远程端口默认为可分配第一个空闲端口

    fcm mossfrp <code>             进入交互式创建mossfrp隧道流程
    fcm mossfrp <code> <local_port> [options]
    fcm mossfrp <code> <local_ip:local_port> [options]
    fcm mossfrp <code> <local_port> <remote_port_num> [options]
    fcm mossfrp <code> <local_ip:local_port> <remote_port_num> [options]
        -p, --protocol <protocol>  协议类型，可选tcp/udp，默认tcp
        -n, --name <name>          隧道名称，默认空

`fcm listservers`:列出所有服务端

`fcm listtunnels`:列出所有隧道

`fcm delserver`:删除一个服务端

    fcm delserver <name>           删除指定名称的服务端

`fcm deltunnel`:删除一个隧道

    fcm deltunnel <name>           删除指定名称的隧道
