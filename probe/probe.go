//probe 在 Unikraft Cloud unikernel 内逐项检测 fanout 的运行时依赖，
//把 JSON 结果打印到 stdout（进实例日志）并在 :8080/probe 提供 HTTP 获取。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type result struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Errno   string `json:"errno,omitempty"`
	Verdict string `json:"verdict,omitempty"`
}

func errnoName(err error) string {
	if en, ok := err.(syscall.Errno); ok {
		return fmt.Sprintf("ERRNO_%d(%s)", uint(en), en.Error())
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func add(rs *[]result, name string, ok bool, detail string, err error, verdict string) {
	r := result{Name: name, OK: ok, Detail: detail, Verdict: verdict}
	if err != nil {
		r.Errno = errnoName(err)
	}
	*rs = append(*rs, r)
}

func main() {
	// 子进程模式：被父进程 exec 起来验证多进程能力，立即退出
	if os.Getenv("PROBE_CHILD") == "1" {
		os.Exit(0)
	}

	rs := []result{}

	// --- 身份/内核 ---
	add(&rs, "identity.geteuid", os.Geteuid() == 0, fmt.Sprintf("euid=%d pid=%d", os.Geteuid(), os.Getpid()), nil,
		"fanout 需要 root")

	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		add(&rs, "identity.uname", false, "", err, "")
	} else {
		add(&rs, "identity.uname", true, fmt.Sprintf("sysname=%s release=%s machine=%s",
			chars(uts.Sysname[:]), chars(uts.Release[:]), chars(uts.Machine[:])), nil, "")
	}

	// --- 文件系统：fanout 工作目录 ---
	dir := "/var/lib/fanout"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		add(&rs, "fs.workdir", false, dir, err, "fanout 启动即 Fatal")
	} else {
		lock := filepath.Join(dir, ".probe-write")
		err := os.WriteFile(lock, []byte("probe"), 0o600)
		add(&rs, "fs.workdir", err == nil, dir+" 写入"+lock, err, "fanout state.json 落盘依赖")
	}

	// --- netns：initMainNetns 的直接依赖 ---
	if f, err := os.Open("/proc/self/ns/net"); err != nil {
		add(&rs, "netns.open_proc_self_ns_net", false, "/proc/self/ns/net", err, "fanout main.go initMainNetns 首个 Fatal 点")
	} else {
		link, _ := os.Readlink("/proc/self/ns/net")
		add(&rs, "netns.open_proc_self_ns_net", true, link, nil, "")
		f.Close()
	}

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		add(&rs, "netns.unshare_CLONE_NEWNET", false, "unshare(CLONE_NEWNET)", err, "fanout 建隧道 netns 依赖")
	} else {
		add(&rs, "netns.unshare_CLONE_NEWNET", true, "", nil, "")
	}

	if err := os.MkdirAll("/var/run/netns", 0o755); err != nil {
		add(&rs, "netns.mkdir_var_run_netns", false, "/var/run/netns", err, "ip netns add 等价路径")
	} else {
		add(&rs, "netns.mkdir_var_run_netns", true, "", nil, "")
	}

	// --- TUN：openvpn 依赖 ---
	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		add(&rs, "tun.open_dev_net_tun", false, "/dev/net/tun", err, "openvpn 隧道硬依赖")
		// 尝试 mknod 兜底
		_ = os.MkdirAll("/dev/net", 0o755)
		if mkErr := unix.Mknod("/dev/net/tun", 0o600, int(unix.Mkdev(10, 200))); mkErr != nil {
			add(&rs, "tun.mknod_retry", false, "mknod(10,200)", mkErr, "无 devtmpfs 自动创建")
		} else if tun2, err2 := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err2 != nil {
			add(&rs, "tun.mknod_retry", false, "mknod 后重开", err2, "")
			tun = nil
		} else {
			add(&rs, "tun.mknod_retry", true, "mknod 成功", nil, "")
			tun = tun2
		}
	} else {
		add(&rs, "tun.open_dev_net_tun", true, "", nil, "")
	}
	if tun != nil {
		defer tun.Close()
		ifr := make([]byte, 16) // IFNAMSIZ
		copy(ifr, []byte("probe0\x00"))
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tun.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
		if errno != 0 {
			add(&rs, "tun.ioctl_TUNSETIFF", false, "TUNSETIFF probe0", errno, "openvpn ioctl 依赖")
		} else {
			add(&rs, "tun.ioctl_TUNSETIFF", true, "", nil, "")
		}
	}

	// --- 外部二进制：ip/iptables/openvpn ---
	for _, bin := range []string{"ip", "iptables", "openvpn"} {
		_, err := exec.LookPath(bin)
		if err != nil {
			add(&rs, "exec.lookup."+bin, false, "PATH="+os.Getenv("PATH"), err, "fanout 拨号/防火墙依赖外部命令")
		} else {
			add(&rs, "exec.lookup."+bin, true, "", nil, "")
		}
	}

	// --- 多进程能力：exec 自身（unikernel 预期 ENOSYS/EPERM）---
	self, selfErr := os.Executable()
	if selfErr != nil || self == "" {
		self = os.Args[0]
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), "PROBE_CHILD=1")
	if err := cmd.Run(); err != nil {
		add(&rs, "exec.self_fork_exec", false, self, err, "fanout exec openvpn/xray 的硬前提")
	} else {
		add(&rs, "exec.self_fork_exec", true, self, nil, "多进程可用")
	}

	// --- 出网：vpngate 列表 + GitHub + DNS ---
	httpClient := &http.Client{Timeout: 10 * time.Second}
	for _, target := range []struct {
		name, url string
	}{
		{"vpngate_csv", "http://www.vpngate.net/api/iphone/"},
		{"github_api", "https://api.github.com"},
	} {
		t0 := time.Now()
		resp, err := httpClient.Get(target.url)
		if err != nil {
			add(&rs, "egress."+target.name, false, target.url, err, "节点列表/更新检查出网")
			continue
		}
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		add(&rs, "egress."+target.name, resp.StatusCode >= 200 && resp.StatusCode < 400,
			fmt.Sprintf("status=%d first_bytes=%q elapsed=%s", resp.StatusCode, buf[:n], time.Since(t0).Round(time.Millisecond)), nil, "")
	}
	if ips, err := net.LookupIP("www.vpngate.net"); err != nil {
		add(&rs, "egress.dns_vpngate", false, "", err, "")
	} else {
		add(&rs, "egress.dns_vpngate", len(ips) > 0, fmt.Sprintf("ips=%v", ips), nil, "")
	}

	out, _ := json.MarshalIndent(map[string]any{"probe": "fanout-unikraft-feasibility", "results": rs}, "", "  ")
	fmt.Println(string(out))

	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	log.Println("probe listening :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func chars(a []int8) string {
	b := make([]byte, 0, len(a))
	for _, c := range a {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
