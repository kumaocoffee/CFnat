package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	timeout     = 1500 * time.Millisecond // TLS连接与握手超时
	maxDuration = 3 * time.Second         // 最大请求持续时间
)

var (
	activeConnections  int32
	validIPClientCache sync.Map
	randomMu           sync.Mutex
	randomGenerator    = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// IPManager 用于管理多 IP 真实负载均衡池与故障自愈
type IPManager struct {
	mu           sync.RWMutex
	allIPs       []string // 所有经过验证的候选 IP
	activePool   []string // 当前活动的 Top-N 负载均衡 IP 池
	failedIPs    map[string]bool
	currentIndex int // 指向 allIPs 中下一个用于替补的 IP 索引
	rrCounter    uint32
}

func NewIPManager() *IPManager {
	return &IPManager{
		failedIPs: make(map[string]bool),
	}
}

func (m *IPManager) SetIPPool(ips []string, poolSize int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.allIPs = ips
	m.failedIPs = make(map[string]bool)
	m.rrCounter = 0

	if poolSize <= 0 {
		poolSize = 1
	}
	if poolSize > len(ips) {
		poolSize = len(ips)
	}

	m.activePool = make([]string, poolSize)
	copy(m.activePool, ips[:poolSize])
	m.currentIndex = poolSize
}

func (m *IPManager) GetNextTarget() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.activePool) == 0 {
		return ""
	}

	idx := atomic.AddUint32(&m.rrCounter, 1)
	return m.activePool[int(idx)%len(m.activePool)]
}

func (m *IPManager) GetActivePool() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool := make([]string, len(m.activePool))
	copy(pool, m.activePool)
	return pool
}

func (m *IPManager) ReplaceFailedIP(failedIP string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failedIPs[failedIP] = true

	foundIdx := -1
	for i, ip := range m.activePool {
		if ip == failedIP {
			foundIdx = i
			break
		}
	}
	if foundIdx == -1 {
		return "", false
	}

	for m.currentIndex < len(m.allIPs) {
		candidate := m.allIPs[m.currentIndex]
		m.currentIndex++
		if !m.failedIPs[candidate] {
			m.activePool[foundIdx] = candidate
			return candidate, true
		}
	}

	// 无可用替补时缩减活跃池
	m.activePool = append(m.activePool[:foundIdx], m.activePool[foundIdx+1:]...)
	return "", false
}

func (m *IPManager) IsAllFailed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.activePool) == 0
}

func (m *IPManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allIPs = nil
	m.activePool = nil
	m.failedIPs = make(map[string]bool)
	m.currentIndex = 0
	m.rrCounter = 0
}

func isAbnormalIP(ip string) bool {
	cleanIP := strings.TrimSpace(ip)
	if strings.Contains(cleanIP, "/") {
		cleanIP = strings.Split(cleanIP, "/")[0]
	}
	if strings.HasPrefix(cleanIP, "1.0.0.") ||
		strings.HasPrefix(cleanIP, "1.1.1.") ||
		strings.HasPrefix(cleanIP, "8.8.8.") ||
		strings.HasPrefix(cleanIP, "8.8.4.") ||
		strings.HasPrefix(cleanIP, "9.9.9.") ||
		strings.HasPrefix(cleanIP, "114.114.114.") ||
		strings.HasPrefix(cleanIP, "223.5.5.") ||
		strings.HasPrefix(cleanIP, "223.6.6.") ||
		strings.HasPrefix(cleanIP, "127.") ||
		strings.HasPrefix(cleanIP, "0.") ||
		strings.HasPrefix(cleanIP, "10.") ||
		strings.HasPrefix(cleanIP, "192.168.") {
		return true
	}
	return false
}

type result struct {
	ip          string        // IP地址
	dataCenter  string        // 数据中心
	region      string        // 地区
	city        string        // 城市
	latency     string        // 延迟字符串
	tcpDuration time.Duration // TCP请求延迟
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

func main() {
	localAddr := flag.String("addr", "0.0.0.0:1234", "本地监听的 IP 和端口")
	code := flag.Int("code", 200, "HTTP/HTTPS 响应状态码")
	coloFilter := flag.String("colo", "", "筛选数据中心例如 HKG,SJC,LAX (多个数据中心用逗号隔开,留空则忽略匹配)")
	Delay := flag.Int("delay", 400, "有效延迟（毫秒），超过此延迟将断开连接")
	domain := flag.String("domain", "cloudflaremirrors.com/debian", "响应状态码检查的域名地址")
	ipCount := flag.Int("ipnum", 20, "提取的有效IP数量")
	ipsType := flag.String("ips", "4", "指定生成IPv4还是IPv6地址 (4或6)")
	num := flag.Int("num", 8, "目标负载 IP 数量")
	port := flag.Int("port", 443, "转发的目标端口")
	random := flag.Bool("random", true, "是否随机生成IP，如果为false，则从CIDR中拆分出所有IP")
	maxThreads := flag.Int("task", 100, "并发请求最大协程数")
	useTLS := flag.Bool("tls", true, "是否为 TLS 端口")
	scanOnly := flag.Bool("scan", false, "仅执行测速与生成缓存文件后退出，不启动监听服务")

	flag.Parse()

	if *scanOnly {
		log.Println("以纯测速模式启动 (-scan)，开始执行 TLS 443 优选扫描...")
		locations, err := loadLocations()
		if err != nil {
			log.Fatalf("加载位置信息失败: %v", err)
		}
		locationMap := make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}

		var url string
		var filename string
		switch *ipsType {
		case "6":
			filename = "ips-v6.txt"
			url = "https://www.baipiao.eu.org/cloudflare/ips-v6"
		case "4":
			filename = "ips-v4.txt"
			url = "https://www.baipiao.eu.org/cloudflare/ips-v4"
		default:
			log.Println("无效的IP类型。请使用 '4' 或 '6'")
			return
		}

		var content string
		if _, err = os.Stat(filename); os.IsNotExist(err) {
			fmt.Printf("文件 %s 不存在，正在从 URL %s 下载数据\n", filename, url)
			content, err = getURLContent(url)
			if err != nil {
				log.Fatalf("获取URL内容出错: %v", err)
			}
			_ = saveToFile(filename, content)
		} else {
			content, err = getFileContent(filename)
			if err != nil {
				log.Fatalf("读取本地文件出错: %v", err)
			}
		}

		var ipList []string
		if *random {
			ipList = parseIPList(content)
			switch *ipsType {
			case "6":
				ipList = getRandomIPv6s(ipList)
			case "4":
				ipList = getRandomIPv4s(ipList)
			}
		} else {
			ipList, err = readIPs(filename)
			if err != nil {
				log.Fatalf("读取IP出错: %v", err)
			}
		}

		fmt.Println("开始执行 TLS 443 节点测速与数据中心识别...")
		results := scanIPs(ipList, locationMap, *maxThreads)
		if len(results) > 0 {
			saveToCSV(filepath.Join("colo", "ip.csv"), results)
			saveToCSV("ip.csv", results)
			fmt.Printf("扫描完成！共获取 %d 个有效节点，已更新至 ip.csv\n", len(results))
		} else {
			fmt.Println("未发现任何有效节点。")
		}
		return
	}

	ipManager := NewIPManager()

	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("无法监听 %s: %v", *localAddr, err)
	}
	defer listener.Close()

	log.Printf("正在监听 %s，负载池容量: %d，延迟门限: %d ms", *localAddr, *num, *Delay)

	for {
		startTime := time.Now()

		locations, err := loadLocations()
		if err != nil {
			log.Printf("加载位置信息失败: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		locationMap := make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}

		var results []result

		// 步骤 1: 优先尝试读取已有的 ip.csv 缓存，避免重复漫长测速
		csvPaths := []string{filepath.Join("colo", "ip.csv"), "ip.csv"}
		results = loadFromCSV(csvPaths, *coloFilter, time.Duration(*Delay)*time.Millisecond, locationMap)
		if len(results) > 0 {
			fmt.Printf("从本地 ip.csv 成功命中并加载 %d 个优选 IP（匹配数据中心: %s），免除二次扫描！\n", len(results), *coloFilter)
		} else {
			// 未命中 CSV 缓存时，执行网络扫描
			var url string
			var filename string

			switch *ipsType {
			case "6":
				filename = "ips-v6.txt"
				url = "https://www.baipiao.eu.org/cloudflare/ips-v6"
			case "4":
				filename = "ips-v4.txt"
				url = "https://www.baipiao.eu.org/cloudflare/ips-v4"
			default:
				fmt.Println("无效的IP类型。请使用 '4' 或 '6'")
				return
			}

			var content string
			if _, err = os.Stat(filename); os.IsNotExist(err) {
				fmt.Printf("文件 %s 不存在，正在从 URL %s 下载数据\n", filename, url)
				content, err = getURLContent(url)
				if err != nil {
					fmt.Println("获取URL内容出错:", err)
					return
				}
				_ = saveToFile(filename, content)
			} else {
				content, err = getFileContent(filename)
				if err != nil {
					fmt.Println("读取本地文件出错:", err)
					return
				}
			}

			var ipList []string
			if *random {
				ipList = parseIPList(content)
				switch *ipsType {
				case "6":
					ipList = getRandomIPv6s(ipList)
				case "4":
					ipList = getRandomIPv4s(ipList)
				}
			} else {
				ipList, err = readIPs(filename)
				if err != nil {
					fmt.Println("读取IP出错:", err)
					return
				}
			}

			fmt.Println("开始执行 TLS 443 节点测速与数据中心识别...")
			results = scanIPs(ipList, locationMap, *maxThreads)

			// 自动保存扫描结果供后续使用
			if len(results) > 0 {
				saveToCSV(filepath.Join("colo", "ip.csv"), results)
				saveToCSV("ip.csv", results)
			}

			// 数据中心过滤（支持空白符修剪）
			if *coloFilter != "" {
				rawFilters := strings.Split(*coloFilter, ",")
				var filters []string
				for _, f := range rawFilters {
					f = strings.TrimSpace(f)
					if f != "" {
						filters = append(filters, strings.ToUpper(f))
					}
				}
				var filteredResults []result
				for _, r := range results {
					for _, filter := range filters {
						if strings.EqualFold(r.dataCenter, filter) {
							filteredResults = append(filteredResults, r)
							break
						}
					}
				}
				results = filteredResults
			}
		}

		if len(results) == 0 {
			fmt.Println("未发现符合条件的有效 IP，3 秒后重试...")
			time.Sleep(3 * time.Second)
			continue
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].tcpDuration < results[j].tcpDuration
		})

		if len(results) > *ipCount {
			results = results[:*ipCount]
		}

		fmt.Println("IP 地址 | 数据中心 | 地区 | 城市 | 延迟")
		for _, r := range results {
			fmt.Printf("%s | %s | %s | %s | %s\n", r.ip, r.dataCenter, r.region, r.city, r.latency)
		}
		fmt.Printf("成功提取 %d 个优选 IP，耗时 %d 秒\n", len(results), time.Since(startTime)/time.Second)

		var ips []string
		for _, r := range results {
			ips = append(ips, r.ip)
		}

		// 启动零等待：移除前置阻塞测速等待，8 个健康 IP 按延迟优选瞬间填满活跃池，端口即刻就绪
		poolCapacity := *num
		if poolCapacity <= 0 {
			poolCapacity = 8
		}
		ipManager.SetIPPool(ips, poolCapacity)
		log.Printf("[服务就绪] 正在监听 %s，活跃负载池已装填 %d 个优选节点，备选池总数: %d，节点: %v",
			*localAddr, len(ipManager.GetActivePool()), len(ips), ipManager.GetActivePool())

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan bool, 1)

		var loopWG sync.WaitGroup
		loopWG.Add(2)

		// 启动状态巡检
		go func() {
			defer loopWG.Done()
			statusCheck(ctx, *useTLS, *port, done, *domain, *code, time.Duration(*Delay)*time.Millisecond, ipManager)
		}()

		// 主监听接受循环
		go func() {
			defer loopWG.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					if tcpListener, ok := listener.(*net.TCPListener); ok {
						tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
					}
					conn, err := listener.Accept()
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
							return
						}
						continue
					}

					atomic.AddInt32(&activeConnections, 1)
					go handleConnection(conn, ipManager, *port, time.Duration(*Delay)*time.Millisecond)
				}
			}
		}()

		<-done
		cancel()
		loopWG.Wait()

		ipManager.Clear()
		validIPClientCache = sync.Map{}
		log.Println("当前轮次结束，重新检索节点...")
	}
}

// loadFromCSV 从 ip.csv 文件读取已经测速完成的有效数据
func loadFromCSV(csvPaths []string, coloFilter string, maxLatency time.Duration, locationMap map[string]location) []result {
	var cleanFilters []string
	if coloFilter != "" {
		for _, f := range strings.Split(coloFilter, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				cleanFilters = append(cleanFilters, strings.ToUpper(f))
			}
		}
	}

	for _, path := range csvPaths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil || len(records) <= 1 {
			continue
		}

		var results []result
		for _, row := range records[1:] {
			if len(row) < 5 {
				continue
			}
			ip := strings.TrimSpace(row[0])
			if isAbnormalIP(ip) {
				continue
			}
			dc := strings.TrimSpace(strings.ToUpper(row[1]))
			region := strings.TrimSpace(row[2])
			city := strings.TrimSpace(row[3])
			latencyStr := strings.TrimSpace(row[4])

			if len(cleanFilters) > 0 {
				matched := false
				for _, cf := range cleanFilters {
					if dc == cf {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			latencyVal := 0
			fmt.Sscanf(latencyStr, "%d", &latencyVal)
			dur := time.Duration(latencyVal) * time.Millisecond
			if maxLatency > 0 && dur > maxLatency {
				continue
			}

			results = append(results, result{
				ip:          ip,
				dataCenter:  dc,
				region:      region,
				city:        city,
				latency:     fmt.Sprintf("%d ms", latencyVal),
				tcpDuration: dur,
			})
		}

		if len(results) > 0 {
			sort.Slice(results, func(i, j int) bool {
				return results[i].tcpDuration < results[j].tcpDuration
			})
			return results
		}
	}
	return nil
}

func saveToCSV(filename string, results []result) {
	_ = os.MkdirAll(filepath.Dir(filename), 0755)
	file, err := os.Create(filename)
	if err != nil {
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	_ = writer.Write([]string{"IP地址", "数据中心", "地区", "城市", "网络延迟"})
	for _, r := range results {
		_ = writer.Write([]string{r.ip, r.dataCenter, r.region, r.city, r.latency})
	}
}

func loadLocations() ([]location, error) {
	var locations []location

	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在\n正在从 https://www.baipiao.eu.org/cloudflare/locations 下载 locations.json")
		resp, err := http.Get("https://www.baipiao.eu.org/cloudflare/locations")
		if err != nil {
			return nil, fmt.Errorf("无法从URL中获取JSON: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("无法读取响应体: %v", err)
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			return nil, fmt.Errorf("无法解析JSON: %v", err)
		}

		file, err := os.Create("locations.json")
		if err != nil {
			return nil, fmt.Errorf("无法创建文件: %v", err)
		}
		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			return nil, fmt.Errorf("无法写入文件: %v", err)
		}
	} else {
		file, err := os.Open("locations.json")
		if err != nil {
			return nil, fmt.Errorf("无法打开文件: %v", err)
		}
		defer file.Close()

		body, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("无法读取文件: %v", err)
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			return nil, fmt.Errorf("无法解析JSON: %v", err)
		}
	}

	return locations, nil
}

// scanIPs 扫描 IP 列表并返回结果 (基于 TLS 443 + SNI，彻底规避 80 端口阻断)
func scanIPs(ipList []string, locationMap map[string]location, maxThreads int) []result {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []result

	thread := make(chan struct{}, maxThreads)
	var count int32
	var lastPercent int32 = -1
	total := len(ipList)

	for _, ip := range ipList {
		if isAbnormalIP(ip) {
			continue
		}
		wg.Add(1)
		thread <- struct{}{}
		go func(ipAddr string) {
			defer func() {
				<-thread
				wg.Done()
				current := atomic.AddInt32(&count, 1)
				curPercent := int32(float64(current) / float64(total) * 100)
				if curPercent > atomic.LoadInt32(&lastPercent) || int(current) == total {
					if atomic.CompareAndSwapInt32(&lastPercent, atomic.LoadInt32(&lastPercent), curPercent) || int(current) == total {
						fmt.Printf("已完成: %d 总数: %d 已完成: %d%%\n", current, total, curPercent)
					}
				}
			}()

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()
			rawConn, err := dialer.Dial("tcp", net.JoinHostPort(ipAddr, "443"))
			if err != nil {
				return
			}
			defer rawConn.Close()

			tcpDuration := time.Since(start)

			rawConn.SetDeadline(time.Now().Add(maxDuration))
			tlsConn := tls.Client(rawConn, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "cloudflaremirrors.com",
			})
			if err := tlsConn.Handshake(); err != nil {
				return
			}

			// 通过 TLS 发送 HTTP 请求提取 CF-RAY
			req, err := http.NewRequest("GET", "https://cloudflaremirrors.com/", nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Header.Set("Connection", "close")
			req.Close = true

			if err := req.Write(tlsConn); err != nil {
				return
			}

			reader := bufio.NewReader(tlsConn)
			resp, err := http.ReadResponse(reader, req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			cfRay := strings.TrimSpace(resp.Header.Get("CF-RAY"))
			if cfRay == "" {
				return
			}

			parts := strings.Split(cfRay, "-")
			if len(parts) < 2 {
				return
			}

			dataCenter := strings.TrimSpace(strings.ToUpper(parts[len(parts)-1]))
			if dataCenter == "" {
				return
			}

			loc, ok := locationMap[dataCenter]
			mu.Lock()
			if ok {
				fmt.Printf("发现有效IP %s 位置信息 %s 延迟 %d 毫秒\n", ipAddr, loc.City, tcpDuration.Milliseconds())
				results = append(results, result{ipAddr, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			} else {
				fmt.Printf("发现有效IP %s 位置信息未知 延迟 %d 毫秒\n", ipAddr, tcpDuration.Milliseconds())
				results = append(results, result{ipAddr, dataCenter, "", "", fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

func getURLContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}

	var content strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			content.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return content.String(), nil
}

func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func saveToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ipList = append(ipList, line)
		}
	}
	return ipList
}

func nextRandomIntn(n int) int {
	randomMu.Lock()
	defer randomMu.Unlock()
	return randomGenerator.Intn(n)
}

func getRandomIPv4s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" || isAbnormalIP(subnet) {
			continue
		}
		if !strings.Contains(subnet, "/") {
			randomIPs = append(randomIPs, subnet)
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) >= 4 {
			octets[3] = fmt.Sprintf("%d", nextRandomIntn(256))
			randomIP := strings.Join(octets, ".")
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}

func getRandomIPv6s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		if !strings.Contains(subnet, "/") {
			randomIPs = append(randomIPs, subnet)
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/48")
		sections := strings.Split(baseIP, ":")
		if len(sections) >= 3 {
			sections = sections[:3]
			for i := 3; i < 8; i++ {
				sections = append(sections, fmt.Sprintf("%x", nextRandomIntn(65536)))
			}
			randomIP := strings.Join(sections, ":")
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}

// readIPs 从 CIDR 读取 IP，针对 IPv6 及超大网段限制遍历避免 OOM
func readIPs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || isAbnormalIP(line) {
			continue
		}
		if strings.Contains(line, "/") {
			ipAddr, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				return nil, err
			}
			// IPv6 严禁全量遍历，只生成前缀代表性地址
			if ipAddr.To4() == nil {
				ips = append(ips, ipAddr.String())
				continue
			}
			// 对于 IPv4，如果掩码小于 /24，只保留代表性网络地址
			ones, _ := ipNet.Mask.Size()
			if ones < 24 {
				ips = append(ips, line)
				continue
			}
			for currentIP := ipAddr.Mask(ipNet.Mask); ipNet.Contains(currentIP); incrementIP(currentIP) {
				ips = append(ips, currentIP.String())
			}
		} else {
			ips = append(ips, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func checkValidIP(ip string, port int, useTLS bool, domain string, code int) bool {
	address := ip
	if strings.Contains(ip, ":") {
		address = fmt.Sprintf("[%s]", ip)
	}
	cleanDomain := strings.TrimPrefix(domain, "https://")
	cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
	hostOnly := strings.Split(cleanDomain, "/")[0]

	targetURL := fmt.Sprintf("http://%s", cleanDomain)
	if useTLS {
		targetURL = fmt.Sprintf("https://%s", cleanDomain)
	}

	cacheKey := fmt.Sprintf("%s:%d", address, port)
	clientAny, loaded := validIPClientCache.Load(cacheKey)
	var client *http.Client
	if loaded {
		client = clientAny.(*http.Client)
	} else {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         hostOnly,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 3 * time.Second}
				return dialer.DialContext(ctx, network, fmt.Sprintf("%s:%d", address, port))
			},
		}
		newClient := &http.Client{
			Timeout:   4 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		actual, _ := validIPClientCache.LoadOrStore(cacheKey, newClient)
		client = actual.(*http.Client)
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	isValid := (resp.StatusCode == code) || (code == 200 && (resp.StatusCode == 301 || resp.StatusCode == 302))
	return isValid
}

// preflightVerifyIPs 并发预检候选节点可用性
func preflightVerifyIPs(ips []string, port int, useTLS bool, domain string, code int) []string {
	var verifiedIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	maxCheck := len(ips)
	if maxCheck > 50 {
		maxCheck = 50
	}
	candidates := ips[:maxCheck]

	log.Printf("正在并发预检 %d 个候选节点的可用性 (目标端口: %d)...", len(candidates), port)

	sem := make(chan struct{}, 20)
	for _, ip := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(addr string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			if checkValidIP(addr, port, useTLS, domain, code) {
				mu.Lock()
				verifiedIPs = append(verifiedIPs, addr)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	log.Printf("[预检就绪] %d 个候选节点中，%d 个节点通过验证", len(candidates), len(verifiedIPs))
	return verifiedIPs
}

func statusCheck(ctx context.Context, useTLS bool, port int, done chan bool, domain string, code int, delay time.Duration, ipManager *IPManager) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("健康巡检收到退出信号")
			return
		case <-ticker.C:
			activePool := ipManager.GetActivePool()
			if len(activePool) == 0 {
				log.Println("负载池为空，触发全量重新加载")
				done <- true
				return
			}

			for _, ip := range activePool {
				if !checkValidIP(ip, port, useTLS, domain, code) {
					// 抖动防抖重试一次
					time.Sleep(1 * time.Second)
					if !checkValidIP(ip, port, useTLS, domain, code) {
						log.Printf("[健康检查] 节点 %s 连续探测失败，从活跃负载池移除", ip)
						newIP, ok := ipManager.ReplaceFailedIP(ip)
						if ok {
							log.Printf("[健康检查] 成功补充备选节点: %s 至负载池", newIP)
						} else {
							log.Printf("[健康检查] 节点 %s 已移除，当前无可用备选节点", ip)
						}
					}
				}
			}

			if ipManager.IsAllFailed() {
				log.Println("[健康检查] 负载池中所有节点均已失效，触发重新选路")
				done <- true
				return
			}
		}
	}
}

// handleConnection 处理客户端连接，真正实现多 IP 轮询负载均衡与故障实时熔断剔除
func handleConnection(conn net.Conn, ipManager *IPManager, port int, delay time.Duration) {
	defer func() {
		atomic.AddInt32(&activeConnections, -1)
		conn.Close()
	}()

	targetIP := ipManager.GetNextTarget()
	if targetIP == "" {
		log.Println("无可用目标 IP，拒绝连接")
		return
	}

	finalIP := targetIP
	dialTimeout := 2 * time.Second
	targetAddr := net.JoinHostPort(targetIP, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: dialTimeout}
	forwardConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("连接目标 %s 失败 (%v)，立即熔断剔除该故障节点...", targetAddr, err)
		newIP, replaced := ipManager.ReplaceFailedIP(targetIP)
		if replaced {
			log.Printf("[熔断保护] 节点 %s 已剔除，替补节点 %s 加入负载池", targetIP, newIP)
		} else {
			log.Printf("[熔断保护] 节点 %s 已剔除，当前负载池容量: %d", targetIP, len(ipManager.GetActivePool()))
		}

		altIP := ipManager.GetNextTarget()
		if altIP != "" && altIP != targetIP {
			altAddr := net.JoinHostPort(altIP, strconv.Itoa(port))
			forwardConn, err = dialer.Dial("tcp", altAddr)
			if err != nil {
				log.Printf("备用目标 %s 连接亦失败 (%v)，二次熔断剔除...", altAddr, err)
				ipManager.ReplaceFailedIP(altIP)
				return
			}
			targetAddr = altAddr
			finalIP = altIP
		} else {
			log.Println("负载池已无可用节点，终止当前连接")
			return
		}
	}
	defer forwardConn.Close()

	pipeConnections(conn, forwardConn, finalIP, ipManager)
}

func pipeConnections(src, dst net.Conn, targetIP string, ipManager *IPManager) {
	var wg sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = src.Close()
			_ = dst.Close()
		})
	}

	var bytesUp int64
	var bytesDown int64
	var watchdogStarted int32
	var watchdogTimer *time.Timer
	var timerMu sync.Mutex

	stopWatchdog := func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		if watchdogTimer != nil {
			watchdogTimer.Stop()
		}
	}

	wg.Add(2)

	// 上行流量转发: 客户端 (src) -> Cloudflare (dst)
	go func() {
		defer func() {
			stopWatchdog()
			closeBoth()
			wg.Done()
		}()

		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				atomic.AddInt64(&bytesUp, int64(n))

				// 客户端发出首个请求时，立即激活 2 秒断流看门狗 (Watchdog)
				if atomic.CompareAndSwapInt32(&watchdogStarted, 0, 1) {
					timerMu.Lock()
					watchdogTimer = time.AfterFunc(2*time.Second, func() {
						down := atomic.LoadInt64(&bytesDown)
						// 若 2 秒内下行少于 1024 字节（包含 0 字节），判定为僵尸断流/严重卡顿节点
						if down < 1024 {
							log.Printf("[看门狗排雷] 节点 %s 响应断流/过慢 (请求发出后 2 秒下行仅 %d 字节 < 1024B)，立即拉黑淘汰！", targetIP, down)
							newIP, ok := ipManager.ReplaceFailedIP(targetIP)
							if ok {
								log.Printf("[节点补位] 备选优选节点 %s 已即刻晋升至活跃负载池", newIP)
							} else {
								log.Printf("[负载池告警] 节点 %s 已剔除，当前活跃节点数: %d", targetIP, len(ipManager.GetActivePool()))
							}
							// 掐断僵尸连接，促使客户端迅速重试健康节点
							closeBoth()
						}
					})
					timerMu.Unlock()
				}

				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// 下行流量转发: Cloudflare (dst) -> 客户端 (src)
	go func() {
		defer func() {
			stopWatchdog()
			closeBoth()
			wg.Done()
		}()

		buf := make([]byte, 32*1024)
		for {
			n, err := dst.Read(buf)
			if n > 0 {
				atomic.AddInt64(&bytesDown, int64(n))
				// 当下行数据达到 1024 字节，解除看门狗定时器，确认节点畅通可用
				if atomic.LoadInt64(&bytesDown) >= 1024 {
					stopWatchdog()
				}

				if _, werr := src.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
