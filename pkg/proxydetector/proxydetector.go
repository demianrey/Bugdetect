package proxydetector

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Config holds configuration for the Proxy detector
type Config struct {
	Interface  string
	OutputFile *os.File
	Timeout    time.Duration
	ProxyURL   string
}

// Detector represents a proxy vulnerability detector
type Detector struct {
	config   Config
	hosts    sync.Map
	client   *http.Client
	green    *color.Color
}

// NewDetector creates a new proxy detector with the given configuration
func NewDetector(config Config) (*Detector, error) {
	// Parse the proxy URL
	proxyURL, err := url.Parse(config.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Create HTTP client with proxy
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: false,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	return &Detector{
		config:   config,
		hosts:    sync.Map{},
		client:   client,
		green:    color.New(color.FgGreen),
	}, nil
}

// Start begins the proxy detection process
func (d *Detector) Start(ctx context.Context) error {
	// Determine the interface to use
	var interfaceName string
	if d.config.Interface != "" {
		interfaceName = d.config.Interface
	} else {
		iface, err := findDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to find default interface: %w", err)
		}
		interfaceName = iface
	}

	// Open the device for capturing with a reasonable timeout
	handle, err := pcap.OpenLive(interfaceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", interfaceName, err)
	}
	defer handle.Close()

	// Set BPF filter for TCP traffic
	filter := "tcp port 80 or tcp port 443"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Listening on interface %s with filter: %s\n", interfaceName, filter)
	fmt.Fprintf(os.Stderr, "Using proxy: %s\n", d.config.ProxyURL)

	// Use a goroutine to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// Worker pool for validating hosts
	const numWorkers = 5
	workChan := make(chan string, 50)
	
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case host, ok := <-workChan:
					if !ok {
						return
					}
					d.validateHost(host)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Process packets
	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				close(workChan)
				wg.Wait()
				return nil
			}
			
			// Process IPv4 layer to get destination IPs
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				ipStr := ip.DstIP.String()
				
				// Skip private IPs and loopback
				if !isPrivateIP(net.ParseIP(ipStr)) && !isLoopbackIP(net.ParseIP(ipStr)) {
					// Only check if we haven't seen this IP before
					if _, exists := d.hosts.LoadOrStore(ipStr, true); !exists {
						select {
						case workChan <- ipStr:
							// IP sent for validation
						default:
							// Channel full, skip this IP
						}
					}
				}
			}
			
			// Also extract SNI information from ClientHello packets
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				
				// Only look for SNI in TCP packets to port 443
				if tcp.DstPort == 443 {
					payload := tcp.LayerPayload()
					domain := extractSNI(payload)
					if domain != "" {
						// Do not check known non-domains (like IPs)
						if !isIP(domain) && !isLocalDomain(domain) {
							// Only check if we haven't seen this domain before
							if _, exists := d.hosts.LoadOrStore(domain, true); !exists {
								select {
								case workChan <- domain:
									// Domain sent for validation 
								default:
									// Channel full, skip this domain
								}
							}
						}
					}
				}
			}

		case <-ctx.Done():
			close(workChan)
			wg.Wait()
			return nil
		}
	}
}

// isIP checks if a string is an IP address
func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

// Regular expression to find status codes in error messages
var statusCodeRegex = regexp.MustCompile(`(\b[3-5][0-9][0-9]\b)`)

// validateHost checks if a host is vulnerable through proxy
func (d *Detector) validateHost(host string) {
	// Rutas comunes a probar
	pathsToCheck := []string{
		"",
		"/login",
		"/admin",
		"/api",
	}
	
	// Try both HTTP and HTTPS
	for _, protocol := range []string{"http", "https"} {
		// Try each path
		for _, path := range pathsToCheck {
			// Create URL with protocol and host
			urlStr := fmt.Sprintf("%s://%s%s", protocol, host, path)
			req, err := http.NewRequest("HEAD", urlStr, nil)
			if err != nil {
				continue
			}

			// Set standard headers
			req.Header.Set("Host", host)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Accept-Encoding", "gzip, deflate")
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Connection", "keep-alive")

			// Context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), d.config.Timeout)
			req = req.WithContext(ctx)

			// Make the request
			resp, err := d.client.Do(req)
			
			// Handle request errors
			if err != nil {
				// Try to extract status code from error message using regex
				matches := statusCodeRegex.FindStringSubmatch(err.Error())
				if len(matches) > 1 {
					// Found a status code in the error message
					statusCode, _ := strconv.Atoi(matches[1])
					
					// Check if it's one of our target error codes
					if statusCode == 407 || statusCode == 403 || statusCode == 400 {
						// Format the bug info
						bugInfo := ""
						if path != "" && path != "/" {
							bugInfo = fmt.Sprintf("%s%s [%d]", host, path, statusCode)
						} else {
							bugInfo = fmt.Sprintf("%s [%d]", host, statusCode)
						}
						
						// Log the bug
						d.green.Fprintf(os.Stdout, "%s\n", bugInfo)
						fmt.Fprintf(d.config.OutputFile, "%s\n", bugInfo)
						
						// Don't check other paths for this host protocol
						break
					}
				}
				
				cancel()
				continue
			}

			// Process successful response
			if resp != nil {
				statusCode := resp.StatusCode
				resp.Body.Close()
				
				// Check for known proxy vulnerability status codes
				if statusCode == 407 || statusCode == 403 || statusCode == 400 {
					// Format the bug info
					bugInfo := ""
					if path != "" && path != "/" {
						bugInfo = fmt.Sprintf("%s%s [%d]", host, path, statusCode)
					} else {
						bugInfo = fmt.Sprintf("%s [%d]", host, statusCode)
					}
					
					// Log the bug
					d.green.Fprintf(os.Stdout, "%s\n", bugInfo)
					fmt.Fprintf(d.config.OutputFile, "%s\n", bugInfo)
					
					// Don't check other paths for this host protocol
					break
				}
			}
			
			cancel()
		}
	}
}

// extractSNI attempts to extract the SNI from a TLS ClientHello packet
func extractSNI(payload []byte) string {
	// Minimum length for TLS record + handshake + client hello
	if len(payload) < 43 {
		return ""
	}
	
	// Check if it's a TLS handshake
	if payload[0] != 0x16 { // Handshake record type
		return ""
	}
	
	// Skip TLS record header (5 bytes)
	payload = payload[5:]
	
	// Check if it's a client hello
	if len(payload) < 4 || payload[0] != 0x01 { // Client Hello handshake type
		return ""
	}
	
	// Skip handshake header
	payload = payload[4:]
	
	// Skip client version (2 bytes)
	if len(payload) < 2 {
		return ""
	}
	payload = payload[2:]
	
	// Skip client random (32 bytes)
	if len(payload) < 32 {
		return ""
	}
	payload = payload[32:]
	
	// Skip session ID
	if len(payload) < 1 {
		return ""
	}
	sessionIDLength := int(payload[0])
	payload = payload[1:]
	if len(payload) < sessionIDLength {
		return ""
	}
	payload = payload[sessionIDLength:]
	
	// Skip cipher suites
	if len(payload) < 2 {
		return ""
	}
	cipherSuitesLength := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < cipherSuitesLength {
		return ""
	}
	payload = payload[cipherSuitesLength:]
	
	// Skip compression methods
	if len(payload) < 1 {
		return ""
	}
	compressionMethodsLength := int(payload[0])
	payload = payload[1:]
	if len(payload) < compressionMethodsLength {
		return ""
	}
	payload = payload[compressionMethodsLength:]
	
	// Check for extensions
	if len(payload) < 2 {
		return ""
	}
	extensionsLength := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < extensionsLength {
		return ""
	}
	
	// Parse extensions
	extensions := payload[:extensionsLength]
	for len(extensions) >= 4 {
		extensionType := int(extensions[0])<<8 | int(extensions[1])
		extensionLength := int(extensions[2])<<8 | int(extensions[3])
		extensions = extensions[4:]
		
		if len(extensions) < extensionLength {
			break
		}
		
		// Server Name Indication extension
		if extensionType == 0 {
			// Parse SNI extension
			sniData := extensions[:extensionLength]
			if len(sniData) < 2 {
				break
			}
			
			sniListLength := int(sniData[0])<<8 | int(sniData[1])
			sniData = sniData[2:]
			
			if len(sniData) < sniListLength || sniListLength < 3 {
				break
			}
			
			// We only care about the first SNI entry
			if sniData[0] != 0 { // host_name type
				break
			}
			
			hostnameLength := int(sniData[1])<<8 | int(sniData[2])
			sniData = sniData[3:]
			
			if len(sniData) < hostnameLength {
				break
			}
			
			hostname := string(sniData[:hostnameLength])
			return hostname
		}
		
		extensions = extensions[extensionLength:]
	}
	
	return ""
}

// isPrivateIP checks if an IP address is private
func isPrivateIP(ip net.IP) bool {
	// Check if IP is nil
	if ip == nil {
		return false
	}
	
	// Check against private IP ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}

	for _, r := range privateRanges {
		if bytesCompare(ip, r.start) >= 0 && bytesCompare(ip, r.end) <= 0 {
			return true
		}
	}

	return false
}

// isLoopbackIP checks if an IP address is loopback
func isLoopbackIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// bytesCompare compares two IP addresses
func bytesCompare(a, b net.IP) int {
	if len(a) == 16 && len(b) == 4 {
		return bytesCompare(a.To4(), b)
	}
	if len(a) == 4 && len(b) == 16 {
		return bytesCompare(a, b.To4())
	}
	if len(a) == 0 && len(b) > 0 {
		return -1
	}
	if len(a) > 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 && len(b) == 0 {
		return 0
	}

	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// isLocalDomain checks if a domain is local or reserved
func isLocalDomain(domain string) bool {
	return strings.HasSuffix(domain, ".local") ||
		strings.HasSuffix(domain, ".localhost") ||
		strings.HasSuffix(domain, ".internal") ||
		domain == "localhost"
}

// findDefaultInterface attempts to find a suitable network interface for packet capture
func findDefaultInterface() (string, error) {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	
	for _, iface := range interfaces {
		// Skip loopback
		if isLoopback(iface) {
			continue
		}
		
		// Skip interfaces without addresses
		if len(iface.Addresses) == 0 {
			continue
		}
		
		// Return first non-loopback interface with addresses
		return iface.Name, nil
	}
	
	return "", fmt.Errorf("no suitable interface found")
}

// isLoopback checks if an interface is a loopback interface
func isLoopback(iface pcap.Interface) bool {
	for _, addr := range iface.Addresses {
		if addr.IP.IsLoopback() {
			return true
		}
	}
	return false
}