package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Connection represents a network connection between two endpoints
type Connection struct {
	Endpoint1 string
	Port1     uint16
	Endpoint2 string
	Port2     uint16
	Count     int
	Bytes     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// DNSRecord represents a DNS query/response
type DNSRecord struct {
	Query     string
	Response  string
	FirstSeen time.Time
	LastSeen  time.Time
}

// SNIRecord represents a TLS SNI record
type SNIRecord struct {
	Hostname  string
	FirstSeen time.Time
	LastSeen  time.Time
}

// State represents the current state of our network analysis
type State struct {
	Connections map[string]*Connection
	DNSRecords  map[string]*DNSRecord
	SNIRecords  map[string]*SNIRecord
	mu          sync.RWMutex
}

func main() {
	// Parse command line flags
	interfaceName := flag.String("i", "", "Network interface to capture on")
	flag.Parse()

	if *interfaceName == "" {
		log.Fatal("Please specify a network interface using -i flag")
	}

	// Initialize state
	state := &State{
		Connections: make(map[string]*Connection),
		DNSRecords:  make(map[string]*DNSRecord),
		SNIRecords:  make(map[string]*SNIRecord),
	}

	// Start packet capture
	handle, err := pcap.OpenLive(*interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Start cleanup goroutine
	go state.cleanupRoutine()

	// Start display goroutine
	go state.displayRoutine()

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		state.processPacket(packet)
	}
}

// isTLSHandshake checks if the payload contains a TLS handshake
func isTLSHandshake(payload []byte) bool {
	// Check if we have enough data for a TLS record header
	if len(payload) < 5 {
		return false
	}

	// Check if this is a TLS handshake record (0x16)
	if payload[0] != 0x16 {
		return false
	}

	// Check if we have enough data for the handshake header
	if len(payload) < 9 {
		return false
	}

	// Check if this is a Client Hello (type 1)
	if payload[5] != 0x01 {
		return false
	}

	return true
}

// extractSNI extracts the Server Name Indication from a TLS handshake
func extractSNI(payload []byte) (string, bool) {
	// Skip TLS record header (5 bytes)
	handshakeStart := 5

	// Skip handshake header and version
	offset := handshakeStart + 4 + 2 // +2 for version

	// Skip random (32 bytes)
	offset += 32

	// Skip session ID length and session ID
	if len(payload) < offset+1 {
		return "", false
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites length and cipher suites
	if len(payload) < offset+2 {
		return "", false
	}
	cipherSuitesLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + cipherSuitesLen

	// Skip compression methods length and compression methods
	if len(payload) < offset+1 {
		return "", false
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	// Now we're at extensions length
	if len(payload) < offset+2 {
		return "", false
	}
	extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2

	// Parse extensions
	extensionsEnd := offset + extensionsLen
	for offset < extensionsEnd {
		if len(payload) < offset+4 {
			break
		}

		// Get extension type (2 bytes) and length (2 bytes)
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		extLen := int(payload[offset+2])<<8 | int(payload[offset+3])
		offset += 4

		// Check if this is the SNI extension (type 0)
		if extType == 0 {
			// Skip list length
			if len(payload) < offset+2 {
				break
			}
			offset += 2

			// Get name type (should be 0 for hostname)
			if len(payload) < offset+1 || payload[offset] != 0 {
				break
			}
			offset += 1

			// Get name length
			if len(payload) < offset+2 {
				break
			}
			nameLen := int(payload[offset])<<8 | int(payload[offset+1])
			offset += 2

			// Get hostname
			if len(payload) < offset+nameLen {
				break
			}
			hostname := string(payload[offset : offset+nameLen])
			return hostname, true
		}

		// Move to next extension
		offset += extLen
	}

	return "", false
}

// getCanonicalConnectionKey returns a consistent key for a connection regardless of direction
func getCanonicalConnectionKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	// Create two possible connection strings
	conn1 := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	conn2 := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)

	// Return the lexicographically smaller one to ensure consistency
	if conn1 < conn2 {
		return conn1
	}
	return conn2
}

// processPacket handles each captured packet
func (s *State) processPacket(packet gopacket.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Get transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	// Process IP layer (both IPv4 and IPv6)
	var srcIP, dstIP string
	switch ip := networkLayer.(type) {
	case *layers.IPv4:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	case *layers.IPv6:
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	default:
		return
	}

	// Process transport layer (both TCP and UDP)
	var srcPort, dstPort uint16
	switch transport := transportLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(transport.SrcPort)
		dstPort = uint16(transport.DstPort)
	case *layers.UDP:
		srcPort = uint16(transport.SrcPort)
		dstPort = uint16(transport.DstPort)
	default:
		return
	}

	// Update connection state using canonical key
	connKey := getCanonicalConnectionKey(srcIP, srcPort, dstIP, dstPort)
	conn, exists := s.Connections[connKey]
	if !exists {
		// Create new connection with endpoints in canonical order
		if connKey == fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort) {
			conn = &Connection{
				Endpoint1: srcIP,
				Port1:     srcPort,
				Endpoint2: dstIP,
				Port2:     dstPort,
				FirstSeen: time.Now(),
			}
		} else {
			conn = &Connection{
				Endpoint1: dstIP,
				Port1:     dstPort,
				Endpoint2: srcIP,
				Port2:     srcPort,
				FirstSeen: time.Now(),
			}
		}
		s.Connections[connKey] = conn
	}
	conn.Count++
	conn.Bytes += int64(len(packet.Data()))
	conn.LastSeen = time.Now()

	// Process DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		if dns.QR { // This is a response
			for _, answer := range dns.Answers {
				if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
					query := string(dns.Questions[0].Name)
					var response string
					if answer.Type == layers.DNSTypeA {
						response = answer.IP.String()
					} else if answer.Type == layers.DNSTypeAAAA {
						response = answer.IP.String()
					}
					dnsKey := fmt.Sprintf("%s-%s", query, response)
					record, exists := s.DNSRecords[dnsKey]
					if !exists {
						record = &DNSRecord{
							Query:     query,
							Response:  response,
							FirstSeen: time.Now(),
						}
						s.DNSRecords[dnsKey] = record
					}
					record.LastSeen = time.Now()
				}
			}
		}
	}

	// Process TLS layer for SNI (only for TCP)
	if _, ok := transportLayer.(*layers.TCP); ok {
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			payload := appLayer.Payload()
			if isTLSHandshake(payload) {
				if hostname, ok := extractSNI(payload); ok {
					sniKey := hostname
					record, exists := s.SNIRecords[sniKey]
					if !exists {
						record = &SNIRecord{
							Hostname:  hostname,
							FirstSeen: time.Now(),
						}
						s.SNIRecords[sniKey] = record
					}
					record.LastSeen = time.Now()
				}
			}
		}
	}
}

// cleanupRoutine periodically cleans up old entries
func (s *State) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		s.cleanup()
	}
}

// displayRoutine periodically displays the current state
func (s *State) displayRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		s.display()
	}
}

// cleanup removes entries older than 30 seconds
func (s *State) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	threshold := now.Add(-30 * time.Second)

	// Cleanup connections
	for key, conn := range s.Connections {
		if conn.LastSeen.Before(threshold) {
			delete(s.Connections, key)
		}
	}

	// Cleanup DNS records
	for key, record := range s.DNSRecords {
		if record.LastSeen.Before(threshold) {
			delete(s.DNSRecords, key)
		}
	}

	// Cleanup SNI records
	for key, record := range s.SNIRecords {
		if record.LastSeen.Before(threshold) {
			delete(s.SNIRecords, key)
		}
	}
}

// display shows the current state
func (s *State) display() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fmt.Println("\n=== Network State ===")
	fmt.Println("\nConnections:")
	for _, conn := range s.Connections {
		fmt.Printf("%s:%d <-> %s:%d (count: %d, bytes: %d, duration: %s)\n",
			conn.Endpoint1, conn.Port1, conn.Endpoint2, conn.Port2,
			conn.Count, conn.Bytes, conn.LastSeen.Sub(conn.FirstSeen))
	}

	fmt.Println("\nDNS Records:")
	for _, record := range s.DNSRecords {
		fmt.Printf("Query: %s -> Response: %s\n", record.Query, record.Response)
	}

	fmt.Println("\nSNI Records:")
	for _, record := range s.SNIRecords {
		fmt.Printf("Hostname: %s\n", record.Hostname)
	}
}
