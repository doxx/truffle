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

// State represents the current state of our network analysis
type State struct {
	Connections map[string]*Connection
	DNSRecords  map[string]*DNSRecord
	SNIRecords  map[string]*SNIRecord
	mu          sync.RWMutex
	rollupChan  chan NetworkRollup
	debug       bool
}

func main() {
	// Parse command line flags
	interfaceName := flag.String("i", "", "Network interface to capture on")
	apiKey := flag.String("k", "", "OpenAI API key")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	if *interfaceName == "" {
		log.Fatal("Please specify a network interface using -i flag")
	}

	if *apiKey == "" {
		log.Fatal("Please specify OpenAI API key using -k flag")
	}

	// Initialize state
	state := &State{
		Connections: make(map[string]*Connection),
		DNSRecords:  make(map[string]*DNSRecord),
		SNIRecords:  make(map[string]*SNIRecord),
		rollupChan:  make(chan NetworkRollup, 10), // Buffered channel to prevent blocking
		debug:       *debug,
	}

	// Initialize AI session
	aiSession := NewAISession(*apiKey, *debug)
	aiSession.StartAnalysis(state.rollupChan)

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

	// Start rollup goroutine
	go state.rollupRoutine()

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		state.processPacket(packet)
	}
}

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

func isEphemeralPort(port uint16) bool {
	// Ports 49152-65535 are typically ephemeral
	// Some systems use 32768-60999
	return port >= 49152 || (port >= 32768 && port <= 60999)
}

func getCanonicalConnectionKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	srcIsEphemeral := isEphemeralPort(srcPort)
	dstIsEphemeral := isEphemeralPort(dstPort)

	// If one side is ephemeral and the other isn't, use the non-ephemeral port for ordering
	if srcIsEphemeral && !dstIsEphemeral {
		return fmt.Sprintf("%s:ephemeral-%s:%d", srcIP, dstIP, dstPort)
	} else if !srcIsEphemeral && dstIsEphemeral {
		return fmt.Sprintf("%s:%d-%s:ephemeral", srcIP, srcPort, dstIP)
	}

	// If both are ephemeral or both are not, use the original ordering
	conn1 := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	conn2 := fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)

	// Return the lexicographically smaller one to ensure consistency
	if conn1 < conn2 {
		return conn1
	}
	return conn2
}

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
		srcIsEphemeral := isEphemeralPort(srcPort)
		dstIsEphemeral := isEphemeralPort(dstPort)

		if connKey == fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort) {
			conn = &Connection{
				Endpoint1:        srcIP,
				Port1:            srcPort,
				Port1IsEphemeral: srcIsEphemeral,
				Endpoint2:        dstIP,
				Port2:            dstPort,
				Port2IsEphemeral: dstIsEphemeral,
				FirstSeen:        time.Now(),
			}
		} else {
			conn = &Connection{
				Endpoint1:        dstIP,
				Port1:            dstPort,
				Port1IsEphemeral: dstIsEphemeral,
				Endpoint2:        srcIP,
				Port2:            srcPort,
				Port2IsEphemeral: srcIsEphemeral,
				FirstSeen:        time.Now(),
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
			query := string(dns.Questions[0].Name)
			status := dns.ResponseCode.String()

			// Create a DNS record for the query regardless of response type
			dnsKey := fmt.Sprintf("%s-%s", query, status)
			record, exists := s.DNSRecords[dnsKey]
			if !exists {
				record = &DNSRecord{
					Query:     query,
					Response:  status, // For NXDOMAIN, this will be "NXDOMAIN"
					Type:      dns.Questions[0].Type.String(),
					Status:    status,
					FirstSeen: time.Now(),
				}
				s.DNSRecords[dnsKey] = record
			}
			record.LastSeen = time.Now()

			// If we have answers, process them
			if len(dns.Answers) > 0 {
				for _, answer := range dns.Answers {
					if answer.Type == layers.DNSTypeA || answer.Type == layers.DNSTypeAAAA {
						var response string
						if answer.Type == layers.DNSTypeA {
							response = answer.IP.String()
						} else if answer.Type == layers.DNSTypeAAAA {
							response = answer.IP.String()
						}
						// Update the record with the actual response
						record.Response = response
					}
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

func (s *State) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		s.cleanup()
	}
}

func (s *State) displayRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		s.display()
	}
}

func (s *State) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	threshold := now.Add(-30 * time.Second)

	// Track counts before cleanup
	originalConnections := len(s.Connections)
	originalDNS := len(s.DNSRecords)
	originalSNI := len(s.SNIRecords)

	// Cleanup connections
	for key, conn := range s.Connections {
		if conn.LastSeen.Before(threshold) {
			if s.debug {
				log.Printf("Aging out connection: %s:%d <-> %s:%d (last seen: %s)",
					conn.Endpoint1, conn.Port1, conn.Endpoint2, conn.Port2,
					conn.LastSeen.Format(time.RFC3339))
			}
			delete(s.Connections, key)
		}
	}

	// Cleanup DNS records
	for key, record := range s.DNSRecords {
		if record.LastSeen.Before(threshold) {
			if s.debug {
				log.Printf("Aging out DNS record: %s (last seen: %s)",
					record.Query, record.LastSeen.Format(time.RFC3339))
			}
			delete(s.DNSRecords, key)
		}
	}

	// Cleanup SNI records
	for key, record := range s.SNIRecords {
		if record.LastSeen.Before(threshold) {
			if s.debug {
				log.Printf("Aging out SNI record: %s (last seen: %s)",
					record.Hostname, record.LastSeen.Format(time.RFC3339))
			}
			delete(s.SNIRecords, key)
		}
	}

	// Log cleanup results
	if s.debug {
		if originalConnections != len(s.Connections) {
			log.Printf("Aged out %d connections: %d -> %d",
				originalConnections-len(s.Connections),
				originalConnections, len(s.Connections))
		}
		if originalDNS != len(s.DNSRecords) {
			log.Printf("Aged out %d DNS records: %d -> %d",
				originalDNS-len(s.DNSRecords),
				originalDNS, len(s.DNSRecords))
		}
		if originalSNI != len(s.SNIRecords) {
			log.Printf("Aged out %d SNI records: %d -> %d",
				originalSNI-len(s.SNIRecords),
				originalSNI, len(s.SNIRecords))
		}
	}
}

func (s *State) display() {
	if !s.debug {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	fmt.Println("\n=== Network State ===")
	fmt.Println("\nConnections:")
	for _, conn := range s.Connections {
		port1 := fmt.Sprintf("%d", conn.Port1)
		if conn.Port1IsEphemeral {
			port1 = "ephemeral"
		}
		port2 := fmt.Sprintf("%d", conn.Port2)
		if conn.Port2IsEphemeral {
			port2 = "ephemeral"
		}
		fmt.Printf("%s:%s <-> %s:%s (count: %d, bytes: %d, duration: %s)\n",
			conn.Endpoint1, port1, conn.Endpoint2, port2,
			conn.Count, conn.Bytes, conn.LastSeen.Sub(conn.FirstSeen))
	}

	fmt.Println("\nDNS Records:")
	// Aggregate DNS queries by count
	dnsCounts := make(map[string]int)
	for _, record := range s.DNSRecords {
		dnsCounts[record.Query]++
	}
	for query, count := range dnsCounts {
		fmt.Printf("%s %d\n", query, count)
	}

	fmt.Println("\nSNI Records:")
	for _, record := range s.SNIRecords {
		fmt.Printf("%s\n", record.Hostname)
	}
}

func (s *State) rollupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		s.mu.RLock()

		// Collect current state
		rollup := NetworkRollup{
			Timestamp: time.Now(),
		}

		// Copy connections
		for _, conn := range s.Connections {
			rollup.Connections = append(rollup.Connections, *conn)
		}

		// Copy DNS records
		for _, dns := range s.DNSRecords {
			rollup.DNSRecords = append(rollup.DNSRecords, *dns)
		}

		// Copy SNI records
		for _, sni := range s.SNIRecords {
			rollup.SNIRecords = append(rollup.SNIRecords, *sni)
		}

		s.mu.RUnlock()

		// Send rollup to AI (non-blocking)
		select {
		case s.rollupChan <- rollup:
			// Successfully sent
		default:
			// Channel is full, skip this rollup
			log.Println("Warning: Rollup channel full, skipping this interval")
		}
	}
}
