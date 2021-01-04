# goshell

ssh连接多个ip，批量执行命令

使用方法

从命令行传入ip段 共用一个用户名和密码
```
./batchcmd -ipbt 192.168.1.28-38 -u root -p 111111
```

或者

从文件读取ip列表，文件内容格式: ip user password
如果ip都共用一个用户名密码 加上参数： -u user -p password
```
./batchcmd -ipf  /home/iplist
```
