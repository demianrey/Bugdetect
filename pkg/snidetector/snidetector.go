package snidetector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Config holds configuration for the SNI detector
type Config struct {
	Interface  string
	OutputFile io.Writer
	Timeout    time.Duration
}

// Detector represents an SNI traffic detector
type Detector struct {
	config  Config
	domains sync.Map
	green   *color.Color
}

// NewDetector creates a new SNI detector with the given configuration
func NewDetector(config Config) *Detector {
	return &Detector{
		config:  config,
		domains: sync.Map{},
		green:   color.New(color.FgGreen),
	}
}

// Start begins the SNI detection process
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

	// Open the device for capturing
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %w", interfaceName, err)
	}
	defer handle.Close()

	// Set BPF filter for TLS traffic
	filter := "tcp port 443"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Listening on interface %s with filter: %s\n", interfaceName, filter)

	// Use a goroutine to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// Worker pool for validating domains
	const numWorkers = 5
	workChan := make(chan string, 50)
	
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case domain, ok := <-workChan:
					if !ok {
						return
					}
					d.validateSNI(domain)
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
			
			// Process the packet
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			
			tcp, _ := tcpLayer.(*layers.TCP)
			
			// Extract SNI information from TLS ClientHello
			if tcp.DstPort == 443 {
				payload := tcp.LayerPayload()
				domain := extractSNI(payload)
				if domain != "" {
					if _, exists := d.domains.LoadOrStore(domain, true); !exists {
						// New domain found, send for validation
						select {
						case workChan <- domain:
							// No output here
						default:
							// Channel full, skip this domain
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

// validateSNI checks if a domain has SNI vulnerabilities by connecting to 8.8.8.8:443
func (d *Detector) validateSNI(domain string) {
	// Connect directly to 8.8.8.8:443
	conn, err := net.DialTimeout("tcp", "8.8.8.8:443", d.config.Timeout)
	if err != nil {
		// Retry up to 3 times if connection fails
		for i := 0; i < 2; i++ {
			conn, err = net.DialTimeout("tcp", "8.8.8.8:443", d.config.Timeout)
			if err == nil {
				break
			}
		}
		
		if err != nil {
			// Could not connect after retries
			return
		}
	}
	defer conn.Close()
	
	// Perform TLS handshake with SNI
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()
	
	// Set a handshake timeout
	err = tlsConn.SetDeadline(time.Now().Add(d.config.Timeout))
	if err != nil {
		return
	}
	
	// Attempt handshake
	err = tlsConn.Handshake()
	if err != nil {
		// Not a successful SNI bug
		return
	}
	
	// If handshake succeeded, check certificate info
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		
		// Check if this is actually a Google DNS certificate
		if strings.Contains(cert.Subject.CommonName, "dns.google") || 
		   hasDNSGoogleInSAN(cert) {
			// This is a confirmed SNI bug - print and log it
			d.green.Fprintf(os.Stdout, "%s\n", domain)
			fmt.Fprintf(d.config.OutputFile, "%s\n", domain)
		}
	}
}

// hasDNSGoogleInSAN checks if any of the SAN entries contains dns.google
func hasDNSGoogleInSAN(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	
	for _, name := range cert.DNSNames {
		if strings.Contains(name, "dns.google") {
			return true
		}
	}
	
	return false
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