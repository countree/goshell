package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ipfPath = flag.String("ipf", "", "ip地址文件，user passwd 不写将使用默认的用户名密码，文件内容格式: ip user passwd ")
	ipbt    = flag.String("ipbt", "", "ip段例：10.1.1.111-125")
	user    = flag.String("u", "", "默认用户名")
	passwd  = flag.String("p", "", "默认密码")
)

func main() {
	flag.Parse()
	cs := &ClientService{
		IpPath:  *ipfPath,
		Ipbt:    *ipbt,
		DUser:   *user,
		DPasswd: *passwd,
	}
	bindSignal(cs.Exit)
	if checkParams(*ipfPath, *ipbt, *user, *passwd) {
		usageCMD()
		cs.Start()
	}
}

func usageCMD() {
	fmt.Println("命令使用说明")
	fmt.Println("   退出输入：q 或 exit")
	fmt.Println("   scp使用：scp  srcPath  destPath")
	fmt.Println("   save使用，把命令结果保存到本地文件：save  cmd  saveFilePath")
	fmt.Println("   mid使用，把ip和机器id保存到本地文件：mid  saveFilePath")

}

func checkParams(path string, i string, u string, p string) bool {
	if path == "" && i == "" {
		fmt.Println("ipf或ipbt必须选择一个")
		return false
	}
	if i != "" && (u == "" || p == "") {
		fmt.Println("ipbt必须配合u,p一起使用")
		return false
	}
	return true
}
func bindSignal(exit func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	go func() {
		<-sigs
		exit()
	}()
}

type ClientService struct {
	Clients []*SshClient
	IpPath  string
	Ipbt    string
	DUser   string
	DPasswd string
}
type SshClient struct {
	Ip     string
	User   string
	Passwd string
	client *ssh.Client
}

//校验是否符合scp命令
func CheckSCP(cmd string) (string, string, bool) {
	split := strings.Fields(cmd)
	if len(split) == 3 {
		return split[1], split[2], true
	}
	return "", "", false
}
func (c *SshClient) scpFile(session *ssh.Session, cmd string) bool {
	srcp, destp, b := CheckSCP(cmd)
	if !b {
		return false
	}
	var errs error
	go func() {
		file, err := os.Open(srcp)
		if err != nil {
			errs = err
			fmt.Printf("打开文件报错：%s,%v\n", srcp, err)
			return
		}
		info, _ := file.Stat()
		buf := make([]byte, 1024)
		w, _ := session.StdinPipe()
		fmt.Fprintln(w, "C0644", info.Size(), info.Name())
		for {
			n, err := file.Read(buf)
			fmt.Fprint(w, string(buf[:n]))
			if err != nil {
				if err == io.EOF {
					break
				} else {
					fmt.Println("传输文件错误:", err)
				}
			}
		}
		w.Close()
	}()
	if err := session.Run("/usr/bin/scp -qrt " + destp); err != nil {
		if err.Error() != "Process exited with status 1" {
			fmt.Println("scp文件报错：", err.Error())
		}
	}
	return true
}

func (cs *ClientService) Start() {
	defer func() { // 必须要先声明defer，否则不能捕获到panic异常
		if err := recover(); err != nil {
			fmt.Println("参数错误") // 这里的err其实就是panic传入的内容
		}
	}()
	cs.createClients()
	if cs.connectSshClient() {
		cs.waitIn()
	} else {
		fmt.Println("没有可用的连接")
	}
}

func (cs *ClientService) createClients() {
	cs.Clients = make([]*SshClient, 0)
	if cs.IpPath != "" {
		cs.setClientsByIppath()
	} else {
		cs.setClientsByIpbt()
	}
	if len(cs.Clients) <= 0 {
		log.Fatal("没有可用的ip地址")
	} else {
		fmt.Println("可连接的ip地址:", func() string {
			ipall := make([]string, 0)
			for _, c := range cs.Clients {
				ipall = append(ipall, c.Ip)
			}
			return strings.Join(ipall, ",")
		}())
	}
}

//从参数中获取ip列表
func (cs *ClientService) setClientsByIpbt() {
	ipbt := cs.Ipbt
	split := strings.Split(ipbt, "-")
	ipf := split[0]
	if !IsIp(ipf) {
		panic("ip格式错误")
	}
	fa := strings.Split(ipf, ".")
	s, _ := strconv.Atoi(fa[3])
	la := s
	if len(split) >= 2 {
		la, _ = strconv.Atoi(split[1])
	}
	for i := s; i <= la; i++ {
		ipa := append(fa[:3], strconv.Itoa(i))
		cs.Clients = append(cs.Clients, newSshClient(strings.Join(ipa, "."), cs.DUser, cs.DPasswd))
	}
}

//从文件中获取ip列表
func (cs *ClientService) setClientsByIppath() {
	path := cs.IpPath
	if _, err := os.Stat(path); err == nil {
		fb, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal("读取ip文件错误:", err)
		}
		fc := string(fb)
		cl := strings.Split(fc, "\n")
		for _, ltmp := range cl {
			l := strings.ReplaceAll(ltmp, "\n", "")
			l = strings.ReplaceAll(l, "\r", "")
			sa := strings.Fields(l)
			wc := len(sa)
			if l == "" || wc == 0 {
				continue
			}
			ipori := sa[0]
			if !IsIp(ipori) {
				log.Println("ip格式错误:", l)
				continue
			}
			var ip, user, passwd string
			ip = ipori
			if wc == 1 {
				user = cs.DUser
				passwd = cs.DPasswd
			} else if wc == 2 {
				user = sa[1]
				passwd = cs.DPasswd
			} else if wc == 3 {
				user = sa[1]
				passwd = sa[2]
			} else {
				log.Println("格式错误:", l)
				continue
			}
			cs.Clients = append(cs.Clients, newSshClient(ip, user, passwd))
		}
	} else {
		log.Fatal("ip文件不存在:", path)
	}

}
func newSshClient(ip, user, passwd string) *SshClient {
	return &SshClient{
		Ip:     ip,
		User:   user,
		Passwd: passwd,
	}
}
func IsIp(ip string) bool {
	compile, err := regexp.Compile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)$")
	if err != nil {
		return false
	}
	submatch := compile.FindStringSubmatch(ip)
	return len(submatch) == 5 && Check0255(submatch[1]) && Check0255(submatch[2]) && Check0255(submatch[3]) && Check0255(submatch[4])
}
func Check0255(s string) bool {
	i, _ := strconv.Atoi(s)
	return i > 0 && i <= 255
}
func (cs *ClientService) waitIn() {
	defer func() { // 必须要先声明defer，否则不能捕获到panic异常
		if err := recover(); err != nil {
			fmt.Println("命令错误") // 这里的err其实就是panic传入的内容
			cs.waitIn()
		}
	}()

	for {
		fmt.Print("> ")
		inr := bufio.NewReader(os.Stdin)
		inline, err := inr.ReadString('\n')
		if err != nil {
			log.Println("命令错误，请重新输入", err)
			continue
		}
		cmd := strings.TrimSuffix(inline, "\n")
		fields := strings.Fields(cmd)
		if len(fields) == 0 {
			continue
		}
		//如果最后一位是分号;不执行这个命令
		lastword := fields[len(fields)-1]
		if lastword == ";" {
			continue
		}
		//fmt.Println("输入命令为：", cmd)
		s := fields[0]
		if s == "sudo" {
			s = fields[1]
		}
		cmdSpace := strings.Join(fields, " ")
		switch s {
		case "q", "exit":
			cs.Exit()
			return
		case "vim", "vi":
			fmt.Println("不支持命令:", s)
		case "scp":
			if _, _, b := CheckSCP(cmd); !b {
				fmt.Println("格式错误，参考:scp srcFile destPath")
				break
			}
			cs.RunCmd(cmdSpace)
		case "save":
			cs.RunCmdWithOut(strings.Join(fields[1:len(fields)-1], " "), lastword, false)
		case "mid":
			path := checkMid(fields)
			if path == "" {
				fmt.Println("mid  outSaveFile")
				break
			}
			cs.RunCmdWithOut("cat /etc/machine-id", path, true)
		default:
			cs.RunCmd(cmdSpace)
		}
	}
}

/**
校验获取去机器id和ip
*/
func checkMid(fields []string) string {
	p := ""
	if len(fields) >= 3 && fields[0] == "sudo" && fields[1] == "mid" {
		p = fields[2]
	} else if len(fields) >= 2 && fields[0] == "mid" {
		p = fields[1]
	}
	return p
}

func (cs *ClientService) connectSshClient() bool {
	fmt.Print("连接中")
	b := false
	for _, c := range cs.Clients {
		fmt.Print(".")
		ctmp, err := connectToShh(c.Ip, c.User, c.Passwd)
		c.client = ctmp
		if err == nil {
			b = true
		} else {
			fmt.Printf("%s Session创建失败:%s\n", c.Ip, err)
		}
	}
	fmt.Printf("\n连接完成\n")
	return b
}

func (cs *ClientService) RunCmd(cmd string) {
	cs.RunCmdWithOut(cmd, "", false)
}

//outf  命令结果保存到文件
//onel  是否把每个电脑的命令结果合并为一行空格隔开
func (cs *ClientService) RunCmdWithOut(cmd string, outf string, onel bool) {
	var outFile *os.File
	if outf != "" {
		file, _ := os.OpenFile(outf, os.O_CREATE|os.O_TRUNC|os.O_RDWR, os.ModePerm)
		outFile = file
		defer func() {
			fmt.Println("保存结果至文件:", outf)
			outFile.Close()
		}()
	}
	//fmt.Println("执行命令：", cmd)
	//cmd = "ip route|grep 'link src'|awk '{print $9}'&&" + cmd
	for _, c := range cs.Clients {
		if c.client == nil {
			continue
		}
		var in bytes.Buffer
		session, err := c.client.NewSession()
		session.Stdin = &in
		if strings.HasPrefix(cmd, "scp ") {
			c.scpFile(session, cmd)
			_ = session.Close()
			continue
		}
		if strings.Contains(cmd, "sudo ") {
			cmd = strings.ReplaceAll(cmd, "sudo ", "sudo -S ")
			in.WriteString(c.Passwd)
		} else {
			fields := strings.Fields(cmd)
			in.WriteString(fields[len(fields)-1])
		}
		bs, err := session.CombinedOutput(cmd)
		if err != nil {
			fmt.Printf("%s 执行报错：%s,%v\n", c.Ip, string(bs), err)
			continue
		}
		if bs != nil {
			if len(bs) > 0 && bs[0] != 10 && bs[0] != 13 {
				//4k最多
				if len(bs) > 4096 {
					bs = bs[:4096]
				}
				li := len(bs) - 1
				if onel {
					for i, b := range bs {
						if i != li && (b == 10 || b == 13) {
							bs[i] = 32
						}
					}
				}
				if bs[li] != 10 && bs[li] != 13 {
					bs = append(bs, 10)
				}
				oc := string(bs)
				oc = c.Ip + " " + oc
				if outFile != nil {
					_, _ = outFile.WriteString(oc)
				}
				fmt.Print(oc)
			}
		}
	}
	fmt.Println("完成")
}

func (cs *ClientService) Exit() {
	cs.Close()
	os.Exit(0)
}
func (cs *ClientService) Close() {
	log.Println("关闭所有连接")
	for _, c := range cs.Clients {
		if c.client != nil {
			_ = c.client.Close()
		}
	}
}
func connectToShh(ip, user, passwd string) (*ssh.Client, error) {
	sClient, errs := ssh.Dial("tcp", ip+":22", &ssh.ClientConfig{
		Timeout:         time.Second * 10,
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(passwd)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if errs != nil {
		fmt.Printf("\nssh连接失败:%s,%s,%s,%v\n", ip, user, passwd, errs)
	}
	return sClient, errs
}
