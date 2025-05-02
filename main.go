package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/miekg/dns"
)

type ScanResult struct {
	Server   string
	Version  string
	Duration time.Duration
	Error    error
}

func readDNSList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开DNS地址文件失败: %v", err)
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			servers = append(servers, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件错误: %v", err)
	}

	return servers, nil
}

func dnsWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, results chan<- ScanResult, counter *int64) {
	defer wg.Done()

	client := &dns.Client{
		Timeout: 3 * time.Second,
		Net:     "udp",
	}

	for server := range jobs {
		start := time.Now()
		
		msg := new(dns.Msg)
		msg.SetQuestion("version.bind.", dns.TypeTXT)
		msg.Question[0].Qclass = dns.ClassCHAOS

		ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		response, _, err := client.ExchangeContext(ctxTimeout, msg, server+":53")
		
		result := ScanResult{
			Server:   server,
			Duration: time.Since(start),
			Error:    err,
		}

		if response != nil && len(response.Answer) > 0 {
			if t, ok := response.Answer[0].(*dns.TXT); ok {
				result.Version = strings.Trim(t.String(), `"`) // 去除引号
			}
		}

		select {
		case results <- result:
			atomic.AddInt64(counter, 1)
		case <-ctx.Done():
			return
		}
	}
}

func main() {
	// 从文件读取DNS地址
	servers, err := readDNSList("/home/ubuntu/pqm/global_test/version_exp/unable_cache_multiple_upstream.txt")
	if err != nil {
		log.Fatal(err)
	}

	// 初始化进度条（网页1、网页6、网页7推荐方案）
	bar := pb.New(len(servers))
	bar.SetTemplateString(`{{counters . }} {{bar . "[" "=" ">" "-" "]"}} {{percent .}} ({{speed .}}/s)`)
	bar.Start()
	defer bar.Finish()

	// 创建结果文件
	outputFile, err := os.Create("dns_versions.txt")
	if err != nil {
		log.Fatal("无法创建结果文件:", err)
	}
	defer outputFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const workerNum = 20
	var (
		wg      sync.WaitGroup
		counter int64 // 原子计数器（网页3、网页4并发方案）
	)

	jobs := make(chan string, 100)
	results := make(chan ScanResult, 100)

	// 启动worker池
	for i := 0; i < workerNum; i++ {
		wg.Add(1)
		go dnsWorker(ctx, &wg, jobs, results, &counter)
	}

	// 结果处理协程
	go func() {
		for res := range results {
			if res.Error == nil {
				line := fmt.Sprintf("%s: %s\n", res.Server, res.Version)
				if _, err := outputFile.WriteString(line); err != nil {
					log.Printf("写入失败 %s: %v", res.Server, err)
				}
			} else {
				log.Printf("%s查询失败: %v (耗时%s)", res.Server, res.Error, res.Duration)
			}
		}
	}()

	// 进度更新协程（网页6推荐方案）
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				bar.SetCurrent(atomic.LoadInt64(&counter))
			case <-ctx.Done():
				return
			}
		}
	}()

	// 分发任务
	go func() {
		for _, server := range servers {
			select {
			case jobs <- server:
			case <-ctx.Done():
				return
			}
		}
		close(jobs)
	}()

	// 等待所有任务完成
	wg.Wait()
	close(results)
	bar.SetCurrent(int64(len(servers))) // 确保进度条100%
}
