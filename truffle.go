package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

type Session struct {
	SourceIP        string
	SourcePort      int
	DestinationIP   string
	DestinationPort int
	Protocol        string
	SNI             string
	DNSQuery        string
	StartTime       time.Time
	LastSeen        time.Time
	BytesSent       int64
	BytesReceived   int64
	Count           int
}

type CompressedSession struct {
	SourceIP        string
	SourcePort      int
	DestinationIP   string
	DestinationPort int
	Protocol        string
	Count           int
	TotalBytes      int64
	Duration        time.Duration
	FirstSeen       time.Time
	LastSeen        time.Time
}

type NetworkSnapshot struct {
	Sessions   []Session
	SNIs       []string
	DNSQueries []string
	Timestamp  time.Time
}

type AIAnalysis struct {
	Ignore []struct {
		Description string `json:"description"`
		Details     []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		} `json:"details"`
	} `json:"IGNORE"`
	Bad []struct {
		Description string `json:"description"`
		Details     struct {
			Source       string `json:"source"`
			Destination  string `json:"destination"`
			SessionCount int    `json:"session_count"`
			TotalBytes   string `json:"total_bytes"`
		} `json:"details"`
	} `json:"BAD"`
	Summary string `json:"SUMMARY"`
}

type OpenAIResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type IgnorePattern struct {
	Type  string
	Value string
}

type IgnoreStats struct {
	// Count of unique patterns being ignored
	UniquePatterns struct {
		IPPairs    int
		DNSQueries int
		SNIHosts   int
		Ports      int
		IPs        int
	}
	// Count of packets matching ignore patterns
	PacketCounts struct {
		IPPairs    int
		DNSQueries int
		SNIHosts   int
		Ports      int
		IPs        int
	}
}

var (
	interfaceName     = flag.String("i", "", "Network interface to monitor")
	apiKey            = flag.String("k", "", "OpenAI API key")
	debugMode         = flag.Bool("debug", false, "Enable debug mode for verbose output")
	debugAIMode       = flag.Bool("debug-ai", false, "Enable AI conversation debugging")
	sessions          = make(map[string]Session)
	sessionMutex      = &sync.RWMutex{}
	logger            = logrus.New()
	aiSessionID       string
	chatHistory       []map[string]string
	ignorePatterns    []IgnorePattern
	ignoreStats       IgnoreStats
	hasIgnorePatterns bool // Track if we've received any ignore patterns
)

// TLS record types
const (
	TLSHandshakeType uint8 = 22 // Handshake record type
	TLSClientHello   uint8 = 1  // ClientHello message type
)

// TLS extension types
const (
	TLSExtServerName = 0
)

func main() {
	flag.Parse()

	if *interfaceName == "" {
		log.Fatal("Please specify a network interface with -i")
	}

	if *apiKey == "" {
		log.Fatal("Please specify OpenAI API key with -k")
	}

	// Configure logging
	logger.SetLevel(logrus.InfoLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logger.Info("Starting Truffle network monitor")
	logger.Infof("Monitoring interface: %s", *interfaceName)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start packet capture
	go capturePackets(*interfaceName)

	// Start snapshot timer
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Create a snapshot of current sessions
				sessionMutex.RLock()
				snapshot := NetworkSnapshot{
					Timestamp: time.Now(),
				}
				for _, session := range sessions {
					snapshot.Sessions = append(snapshot.Sessions, session)
				}
				sessionMutex.RUnlock()

				// Print session statistics
				printSessionStats(snapshot)

				// Send snapshot to OpenAI
				response := sendSnapshot(snapshot)
				if response != "" {
					// Process AI response to update monitoring rules
					pruneSessions(response)
				}
			case <-sigChan:
				return
			}
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logger.Info("Shutting down...")
}

func capturePackets(iface string) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		logger.Fatal(err)
	}
	defer handle.Close()

	logger.Infof("Starting packet capture on interface %s", iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	if *debugMode {
		logger.Debugf("Processing packet: %s", packet.String())
	}

	// Extract network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Extract transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	// Get source and destination ports
	srcPort, err := strconv.Atoi(transportLayer.TransportFlow().Src().String())
	if err != nil {
		if *debugMode {
			logger.Debugf("Error converting source port %s to integer: %v", transportLayer.TransportFlow().Src().String(), err)
		}
		return
	}

	dstPort, err := strconv.Atoi(transportLayer.TransportFlow().Dst().String())
	if err != nil {
		if *debugMode {
			logger.Debugf("Error converting destination port %s to integer: %v", transportLayer.TransportFlow().Dst().String(), err)
		}
		return
	}

	// Determine which IP is the client and which is the server
	srcIP := networkLayer.NetworkFlow().Src().String()
	dstIP := networkLayer.NetworkFlow().Dst().String()

	// If destination port is well-known (0-1023) and source port is not,
	// then the source is the client and destination is the server
	if dstPort <= 1023 && srcPort > 1023 {
		// Keep as is
	} else if srcPort <= 1023 && dstPort > 1023 {
		// Swap source and destination
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	} else {
		// If both ports are well-known or both are not,
		// assume the lower port is the server
		if srcPort > dstPort {
			srcIP, dstIP = dstIP, srcIP
			srcPort, dstPort = dstPort, srcPort
		}
	}

	// Create session key
	sessionKey := fmt.Sprintf("%s:%d:%s:%d",
		srcIP,
		srcPort,
		dstIP,
		dstPort)

	// Create a temporary session to check if it should be ignored
	tempSession := Session{
		SourceIP:        srcIP,
		SourcePort:      srcPort,
		DestinationIP:   dstIP,
		DestinationPort: dstPort,
		Protocol:        transportLayer.LayerType().String(),
	}

	// Check if this session should be ignored
	if shouldIgnore(tempSession) {
		if *debugMode {
			logger.Debugf("Ignoring session %s based on ignore patterns", sessionKey)
		}
		return
	}

	// Update or create session
	sessionMutex.Lock()
	session, exists := sessions[sessionKey]
	if !exists {
		session = Session{
			SourceIP:        srcIP,
			SourcePort:      srcPort,
			DestinationIP:   dstIP,
			DestinationPort: dstPort,
			Protocol:        transportLayer.LayerType().String(),
			StartTime:       time.Now(),
			LastSeen:        time.Now(),
			Count:           1,
		}
	} else {
		session.Count++
		session.LastSeen = time.Now()
	}

	// Update byte counts
	packetLength := len(packet.Data())
	if networkLayer.NetworkFlow().Src().String() == srcIP {
		session.BytesSent += int64(packetLength)
	} else {
		session.BytesReceived += int64(packetLength)
	}

	// Check for DNS
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		if *debugMode {
			logger.Debug("DNS packet detected")
		}
		dns, ok := dnsLayer.(*layers.DNS)
		if ok && dns.QR == false { // Only process DNS queries
			for _, question := range dns.Questions {
				query := string(question.Name)
				// Create a temporary session with DNS query to check if it should be ignored
				tempSession.DNSQuery = query
				if shouldIgnore(tempSession) {
					if *debugMode {
						logger.Debugf("Ignoring DNS query %s based on ignore patterns", query)
					}
					continue
				}
				session.DNSQuery = query
				if *debugMode {
					logger.Debugf("Extracted DNS query: %s", query)
				}
			}
		}
	}

	// Check for TLS
	if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
		if *debugMode {
			logger.Debug("TLS packet detected")
		}
		session.Protocol = "TLS"

		// Get the raw bytes from the TLS layer
		payload := tlsLayer.LayerPayload()
		if len(payload) > 0 {
			// Try to parse the TLS handshake
			if sni, err := parseTLSHandshake(payload); err == nil && sni != "" {
				// Create a temporary session with SNI to check if it should be ignored
				tempSession.SNI = sni
				if shouldIgnore(tempSession) {
					if *debugMode {
						logger.Debugf("Ignoring SNI %s based on ignore patterns", sni)
					}
				} else {
					session.SNI = sni
					if *debugMode {
						logger.Debugf("Extracted SNI: %s", session.SNI)
					}
				}
			} else if *debugMode && err != nil {
				logger.Debugf("Failed to parse TLS handshake: %v", err)
			}
		}
	}

	sessions[sessionKey] = session
	if *debugMode {
		logger.Debugf("Updated session table: %d sessions", len(sessions))
	}
	sessionMutex.Unlock()
}

func compressSessions(sessions map[string]Session) []CompressedSession {
	compressed := make(map[string]CompressedSession)

	for _, session := range sessions {
		// Create a key for compression based on source IP and destination IP:port
		// For single sessions, include the source port in the key
		key := fmt.Sprintf("%s:%s:%d",
			session.SourceIP,
			session.DestinationIP,
			session.DestinationPort)

		compressedSession, exists := compressed[key]
		if !exists {
			compressedSession = CompressedSession{
				SourceIP:        session.SourceIP,
				SourcePort:      session.SourcePort, // Store the actual source port
				DestinationIP:   session.DestinationIP,
				DestinationPort: session.DestinationPort,
				Protocol:        session.Protocol,
				Count:           1,
				TotalBytes:      session.BytesSent + session.BytesReceived,
				FirstSeen:       session.StartTime,
				LastSeen:        session.LastSeen,
			}
		} else {
			compressedSession.Count++
			compressedSession.TotalBytes += session.BytesSent + session.BytesReceived
			if session.StartTime.Before(compressedSession.FirstSeen) {
				compressedSession.FirstSeen = session.StartTime
			}
			if session.LastSeen.After(compressedSession.LastSeen) {
				compressedSession.LastSeen = session.LastSeen
			}
			// If we have multiple sessions, mark the source port as 0 to indicate it should be displayed as "ephemeral"
			compressedSession.SourcePort = 0
		}
		compressed[key] = compressedSession
	}

	// Convert map to slice and calculate averages
	var result []CompressedSession
	for _, session := range compressed {
		session.Duration = session.LastSeen.Sub(session.FirstSeen)
		result = append(result, session)
	}
	return result
}

func printSessionStats(snapshot NetworkSnapshot) {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()

	// Count SNIs and DNS queries
	sniCount := 0
	dnsCount := 0
	for _, session := range snapshot.Sessions {
		if session.SNI != "" {
			sniCount++
		}
		if session.DNSQuery != "" {
			dnsCount++
		}
	}

	// Count unique patterns
	uniquePatterns := struct {
		IPPairs    int
		DNSQueries int
		SNIHosts   int
		Ports      int
		IPs        int
	}{}
	for _, pattern := range ignorePatterns {
		switch pattern.Type {
		case "pair":
			uniquePatterns.IPPairs++
		case "dns":
			uniquePatterns.DNSQueries++
		case "sni":
			uniquePatterns.SNIHosts++
		case "port":
			uniquePatterns.Ports++
		case "ip":
			uniquePatterns.IPs++
		}
	}

	logger.Infof("\n=== Session Statistics ===")
	logger.Infof("Total Sessions: %d", len(snapshot.Sessions))
	logger.Infof("SNI Count: %d", sniCount)
	logger.Infof("DNS Query Count: %d", dnsCount)

	logger.Infof("\nTotal Ignore Patterns:")
	logger.Infof("  • IP Pairs: %d patterns", uniquePatterns.IPPairs)
	logger.Infof("  • DNS Queries: %d patterns", uniquePatterns.DNSQueries)
	logger.Infof("  • SNI Hosts: %d patterns", uniquePatterns.SNIHosts)
	logger.Infof("  • Ports: %d patterns", uniquePatterns.Ports)
	logger.Infof("  • IPs: %d patterns", uniquePatterns.IPs)

	logger.Infof("\nActive Ignored Traffic (this cycle):")
	logger.Infof("  • IP Pairs: %d packets", ignoreStats.PacketCounts.IPPairs)
	logger.Infof("  • DNS Queries: %d packets", ignoreStats.PacketCounts.DNSQueries)
	logger.Infof("  • SNI Hosts: %d packets", ignoreStats.PacketCounts.SNIHosts)
	logger.Infof("  • Ports: %d packets", ignoreStats.PacketCounts.Ports)
	logger.Infof("  • IPs: %d packets", ignoreStats.PacketCounts.IPs)
	logger.Info("========================\n")
}

func printDebugInfo(snapshot NetworkSnapshot, apiStatus string) {
	if !*debugMode {
		return
	}

	// Clear screen and move cursor to top
	fmt.Print("\033[H\033[2J")

	// Print header
	fmt.Println("┌─────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│                            TRUFFLE DEBUG DASHBOARD                           │")
	fmt.Println("├─────────────────────────────────────────────────────────────────────────────┤")

	// Print API Status
	fmt.Printf("│ OpenAI API Status: %-60s │\n", apiStatus)
	fmt.Println("├─────────────────────────────────────────────────────────────────────────────┤")

	// Print Session Table Header
	fmt.Println("│ Active Sessions                                                              │")
	fmt.Println("├─────────────────┬──────────┬─────────────────┬──────────┬────────┬──────────┤")
	fmt.Println("│ Source IP       │ Src Port │ Destination IP  │ Dst Port │ Proto  │ Duration │")
	fmt.Println("├─────────────────┼──────────┼─────────────────┼──────────┼────────┼──────────┤")

	// Print active sessions
	for _, session := range snapshot.Sessions {
		srcPort := "ephemeral"
		if session.SourcePort != 0 {
			srcPort = fmt.Sprintf("%d", session.SourcePort)
		}

		duration := time.Since(session.StartTime)
		durationStr := formatDuration(duration)

		fmt.Printf("│ %-15s │ %-8s │ %-15s │ %-8d │ %-6s │ %-8s │\n",
			session.SourceIP,
			srcPort,
			session.DestinationIP,
			session.DestinationPort,
			session.Protocol,
			durationStr)
	}
	fmt.Println("├─────────────────┴──────────┴─────────────────┴──────────┴────────┴──────────┤")

	// Print SNI and DNS information
	fmt.Println("│ SNI & DNS Information                                                       │")
	fmt.Println("├─────────────────────────────────────────────────────────────────────────────┤")
	fmt.Println("│ SNI Hosts:                                                                  │")
	for _, session := range snapshot.Sessions {
		if session.SNI != "" {
			fmt.Printf("│   • %-70s │\n", session.SNI)
		}
	}
	fmt.Println("│ DNS Queries:                                                                │")
	for _, session := range snapshot.Sessions {
		if session.DNSQuery != "" {
			fmt.Printf("│   • %-70s │\n", session.DNSQuery)
		}
	}
	fmt.Println("└─────────────────────────────────────────────────────────────────────────────┘")
}

func sendSnapshot(snapshot NetworkSnapshot) string {
	// Initialize chat history if empty
	if len(chatHistory) == 0 {
		systemPrompt := `You are a network security expert analyzing network traffic. Categorize traffic into:
1. "IGNORE": patterns to be ignored, specified as:
   - pair:IP:IP - ignore specific IP pairs (e.g., "pair:192.168.1.1:192.168.1.2")
   - port:PORT - ignore traffic to/from specific ports (e.g., "port:80")
   - ip:IP - ignore traffic involving specific IPs (e.g., "ip:192.168.1.1")
   - dns:QUERY - ignore specific DNS queries (e.g., "dns:google.com")
   - sni:HOST - ignore specific SNI hosts (e.g., "sni:google.com")
2. anomalies: unusual patterns with session counts and bytes, this something you will track with context because it might not be serious now but worth nothing and watching.
3. "BAD": malicious activity with session counts and bytes

We will be sending you a snapshot of DNS, SNI, and sessions tables every 30 seconds so keep this history and build context on it.

Note: exfil is only outbound connections that are long lived (multiple API session calls) and data over 100MB.

Respond in this exact JSON format:
{
    "IGNORE": [
        {"type": "pair", "value": "192.168.1.1:192.168.1.2"},
        {"type": "port", "value": "80"},
        {"type": "ip", "value": "192.168.1.1"},
        {"type": "dns", "value": "google.com"},
        {"type": "sni", "value": "google.com"}
    ],
    "BAD": [{"description": "threat", "details": {"source": "ip", "destination": "ip", "session_count": N, "total_bytes": "size"}}],
    "SUMMARY": "A short summary of the analysis"
}`

		chatHistory = []map[string]string{
			{
				"role":    "system",
				"content": systemPrompt,
			},
		}

		if *debugAIMode {
			logger.Info("\n=== Sending System Prompt to OpenAI API ===")
			logger.Info("System Prompt:")
			logger.Info(systemPrompt)
			logger.Info("===========================\n")
		}
	}

	// Add the snapshot to chat history
	prompt := fmt.Sprintf("Analyze this network snapshot:\n%s", formatSnapshot(snapshot))
	chatHistory = append(chatHistory, map[string]string{
		"role":    "user",
		"content": prompt,
	})

	if *debugMode {
		printDebugInfo(snapshot, "Sending request to OpenAI API...")
	}

	if *debugAIMode {
		logger.Info("\n=== Sending Snapshot to OpenAI API ===")
		logger.Info("Prompt:")
		logger.Info(prompt)
		logger.Info("===========================\n")
	}

	// Prepare OpenAI API request with full chat history
	requestBody := map[string]interface{}{
		"model":    "gpt-4o",
		"messages": chatHistory,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		if *debugMode {
			printDebugInfo(snapshot, fmt.Sprintf("Error marshaling request: %v", err))
		}
		if *debugAIMode {
			logger.Errorf("Error marshaling request: %v", err)
		}
		return ""
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		if *debugMode {
			printDebugInfo(snapshot, fmt.Sprintf("Error creating request: %v", err))
		}
		if *debugAIMode {
			logger.Errorf("Error creating request: %v", err)
		}
		return ""
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		if *debugMode {
			printDebugInfo(snapshot, fmt.Sprintf("Error sending request: %v", err))
		}
		if *debugAIMode {
			logger.Errorf("Error sending request: %v", err)
		}
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if *debugMode {
			printDebugInfo(snapshot, fmt.Sprintf("Error reading response: %v", err))
		}
		if *debugAIMode {
			logger.Errorf("Error reading response: %v", err)
		}
		return ""
	}

	if *debugMode {
		printDebugInfo(snapshot, "Received response from OpenAI API")
	}

	if *debugAIMode {
		logger.Info("\n=== OpenAI API Snapshot Response ===")
		logger.Info(string(body))
		logger.Info("===========================\n")
	}

	var openAIResp OpenAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		if *debugMode {
			printDebugInfo(snapshot, fmt.Sprintf("Error parsing response: %v", err))
		}
		if *debugAIMode {
			logger.Errorf("Error parsing response: %v", err)
		}
		return ""
	}

	if len(openAIResp.Choices) > 0 {
		// Add the assistant's response to chat history
		chatHistory = append(chatHistory, map[string]string{
			"role":    "assistant",
			"content": openAIResp.Choices[0].Message.Content,
		})
		return openAIResp.Choices[0].Message.Content
	}
	return ""
}

func pruneSessions(aiResponse string) {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	originalCount := len(sessions)

	// Clean up the response by removing markdown code blocks and JSON comments
	cleanResponse := aiResponse
	if strings.Contains(cleanResponse, "```json") {
		cleanResponse = strings.TrimPrefix(cleanResponse, "```json")
		cleanResponse = strings.TrimSuffix(cleanResponse, "```")
		cleanResponse = strings.TrimSpace(cleanResponse)
	}

	// Remove JSON comments (lines starting with //)
	lines := strings.Split(cleanResponse, "\n")
	var cleanedLines []string
	for _, line := range lines {
		if !strings.Contains(strings.TrimSpace(line), "//") {
			cleanedLines = append(cleanedLines, line)
		}
	}
	cleanResponse = strings.Join(cleanedLines, "\n")

	// Parse the AI response
	var analysis struct {
		Ignore []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"IGNORE"`
		Bad []struct {
			Description string `json:"description"`
			Details     struct {
				Source       string `json:"source"`
				Destination  string `json:"destination"`
				SessionCount int    `json:"session_count"`
				TotalBytes   string `json:"total_bytes"`
			} `json:"details"`
		} `json:"BAD"`
		Summary string `json:"SUMMARY"`
	}
	if err := json.Unmarshal([]byte(cleanResponse), &analysis); err != nil {
		logger.Errorf("Error parsing AI response: %v", err)
		logger.Errorf("Response content: %s", cleanResponse)
		return
	}

	// Count patterns by type before adding new ones
	oldPatterns := struct {
		IPPairs    int
		DNSQueries int
		SNIHosts   int
		Ports      int
		IPs        int
	}{}
	for _, pattern := range ignorePatterns {
		switch pattern.Type {
		case "pair":
			oldPatterns.IPPairs++
		case "dns":
			oldPatterns.DNSQueries++
		case "sni":
			oldPatterns.SNIHosts++
		case "port":
			oldPatterns.Ports++
		case "ip":
			oldPatterns.IPs++
		}
	}

	// Add new ignore patterns to our accumulated list
	if len(analysis.Ignore) > 0 {
		hasIgnorePatterns = true
		// Create a map of existing patterns to avoid duplicates
		existingPatterns := make(map[string]bool)
		for _, pattern := range ignorePatterns {
			existingPatterns[pattern.Type+":"+pattern.Value] = true
		}

		// Add new patterns that we haven't seen before
		for _, ignore := range analysis.Ignore {
			patternKey := ignore.Type + ":" + ignore.Value
			if !existingPatterns[patternKey] {
				pattern := IgnorePattern{
					Type:  ignore.Type,
					Value: ignore.Value,
				}
				ignorePatterns = append(ignorePatterns, pattern)
				existingPatterns[patternKey] = true
			}
		}
	}

	// Count total patterns by type after adding new ones
	totalPatterns := struct {
		IPPairs    int
		DNSQueries int
		SNIHosts   int
		Ports      int
		IPs        int
	}{}
	for _, pattern := range ignorePatterns {
		switch pattern.Type {
		case "pair":
			totalPatterns.IPPairs++
		case "dns":
			totalPatterns.DNSQueries++
		case "sni":
			totalPatterns.SNIHosts++
		case "port":
			totalPatterns.Ports++
		case "ip":
			totalPatterns.IPs++
		}
	}

	logger.Info("\n=== Session Pruning Results ===")
	logger.Infof("Original session count: %d", originalCount)
	logger.Infof("Current session count: %d", len(sessions))
	logger.Infof("Sessions pruned: %d", originalCount-len(sessions))

	logger.Info("\nTotal Ignore Patterns (Accumulated):")
	logger.Infof("  • IP Pairs: %d patterns", totalPatterns.IPPairs)
	logger.Infof("  • DNS Queries: %d patterns", totalPatterns.DNSQueries)
	logger.Infof("  • SNI Hosts: %d patterns", totalPatterns.SNIHosts)
	logger.Infof("  • Ports: %d patterns", totalPatterns.Ports)
	logger.Infof("  • IPs: %d patterns", totalPatterns.IPs)

	logger.Info("\nNew Ignore Patterns (This Cycle):")
	logger.Infof("  • IP Pairs: %d patterns", totalPatterns.IPPairs-oldPatterns.IPPairs)
	logger.Infof("  • DNS Queries: %d patterns", totalPatterns.DNSQueries-oldPatterns.DNSQueries)
	logger.Infof("  • SNI Hosts: %d patterns", totalPatterns.SNIHosts-oldPatterns.SNIHosts)
	logger.Infof("  • Ports: %d patterns", totalPatterns.Ports-oldPatterns.Ports)
	logger.Infof("  • IPs: %d patterns", totalPatterns.IPs-oldPatterns.IPs)

	logger.Info("\nActive Ignored Traffic (this cycle):")
	logger.Infof("  • IP Pairs: %d packets", ignoreStats.PacketCounts.IPPairs)
	logger.Infof("  • DNS Queries: %d packets", ignoreStats.PacketCounts.DNSQueries)
	logger.Infof("  • SNI Hosts: %d packets", ignoreStats.PacketCounts.SNIHosts)
	logger.Infof("  • Ports: %d packets", ignoreStats.PacketCounts.Ports)
	logger.Infof("  • IPs: %d packets", ignoreStats.PacketCounts.IPs)

	// Log AI's categorization
	logger.Info("\nAI Analysis Summary:")
	logger.Infof("Summary: %s", analysis.Summary)
	logger.Infof("Bad sessions: %d", len(analysis.Bad))

	// Log new ignore patterns
	if len(analysis.Ignore) > 0 {
		logger.Info("\nNew Ignore Patterns Added:")
		for _, ignore := range analysis.Ignore {
			logger.Infof("- %s: %s", ignore.Type, ignore.Value)
		}
	}
	if len(analysis.Bad) > 0 {
		logger.Info("\nBad sessions:")
		for i := 0; i < min(3, len(analysis.Bad)); i++ {
			logger.Infof("- %s -> %s (%d sessions, %s): %s",
				analysis.Bad[i].Details.Source,
				analysis.Bad[i].Details.Destination,
				analysis.Bad[i].Details.SessionCount,
				analysis.Bad[i].Details.TotalBytes,
				analysis.Bad[i].Description)
		}
	}
	logger.Info("=============================\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func formatSnapshot(snapshot NetworkSnapshot) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Timestamp: %s\n", snapshot.Timestamp.Format(time.RFC3339)))
	builder.WriteString("\n")

	// Compress sessions before formatting
	compressedSessions := compressSessions(sessions)

	// Create table header
	header := fmt.Sprintf("%-20s %-10s %-20s %-10s %-8s %-8s %-12s %-12s %-12s %-30s %-30s",
		"Source", "SrcPort", "Destination", "DstPort", "Proto", "Sessions", "Avg Bytes", "Total Bytes", "Duration", "SNI", "DNS Query")
	separator := strings.Repeat("-", len(header))

	builder.WriteString(header + "\n")
	builder.WriteString(separator + "\n")

	// Sort sessions by total bytes (descending)
	sort.Slice(compressedSessions, func(i, j int) bool {
		return compressedSessions[i].TotalBytes > compressedSessions[j].TotalBytes
	})

	// Limit the number of sessions to keep token count reasonable
	maxSessions := 50
	if len(compressedSessions) > maxSessions {
		compressedSessions = compressedSessions[:maxSessions]
	}

	// Format each session as a table row
	for _, session := range compressedSessions {
		srcPort := fmt.Sprintf("%d", session.SourcePort)
		if session.Count > 1 {
			srcPort = "ephemeral"
		}

		// Calculate average bytes per session
		avgBytes := session.TotalBytes / int64(session.Count)

		// Format bytes with appropriate unit
		avgBytesStr := formatBytes(avgBytes)
		totalBytesStr := formatBytes(session.TotalBytes)

		// Format duration
		durationStr := formatDuration(session.Duration)

		// Get SNI and DNS query for this session
		var sni, dnsQuery string
		for _, s := range sessions {
			if s.SourceIP == session.SourceIP && s.DestinationIP == session.DestinationIP && s.DestinationPort == session.DestinationPort {
				if s.SNI != "" {
					sni = s.SNI
				}
				if s.DNSQuery != "" {
					dnsQuery = s.DNSQuery
				}
				if sni != "" && dnsQuery != "" {
					break
				}
			}
		}

		// Truncate long SNI and DNS queries
		if len(sni) > 30 {
			sni = sni[:27] + "..."
		}
		if len(dnsQuery) > 30 {
			dnsQuery = dnsQuery[:27] + "..."
		}

		row := fmt.Sprintf("%-20s %-10s %-20s %-10d %-8s %-8d %-12s %-12s %-12s %-30s %-30s",
			session.SourceIP,
			srcPort,
			session.DestinationIP,
			session.DestinationPort,
			session.Protocol,
			session.Count,
			avgBytesStr,
			totalBytesStr,
			durationStr,
			sni,
			dnsQuery)

		builder.WriteString(row + "\n")
	}

	// Add a summary of unique SNIs and DNS queries, but limit the number
	builder.WriteString("\n=== SNI Summary ===\n")
	sniMap := make(map[string]bool)
	for _, session := range sessions {
		if session.SNI != "" {
			sniMap[session.SNI] = true
		}
	}
	// Limit to top 20 unique SNIs
	sniCount := 0
	for sni := range sniMap {
		if sniCount >= 20 {
			break
		}
		builder.WriteString(fmt.Sprintf("%s\n", sni))
		sniCount++
	}

	builder.WriteString("\n=== DNS Query Summary ===\n")
	dnsMap := make(map[string]bool)
	for _, session := range sessions {
		if session.DNSQuery != "" {
			dnsMap[session.DNSQuery] = true
		}
	}
	// Limit to top 20 unique DNS queries
	dnsCount := 0
	for dns := range dnsMap {
		if dnsCount >= 20 {
			break
		}
		builder.WriteString(fmt.Sprintf("%s\n", dns))
		dnsCount++
	}

	return builder.String()
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func parseTLSHandshake(data []byte) (string, error) {
	if len(data) < 5 { // Minimum length for handshake header
		return "", fmt.Errorf("handshake too short")
	}

	// First byte is handshake type
	handshakeType := data[0]
	if handshakeType != TLSClientHello {
		return "", fmt.Errorf("not a client hello")
	}

	// Next 3 bytes are length
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < length+4 {
		return "", fmt.Errorf("handshake length mismatch")
	}

	// Skip version (2 bytes) and random (32 bytes)
	pos := 38
	if pos >= len(data) {
		return "", fmt.Errorf("handshake too short for session id")
	}

	// Skip session id
	sessionIDLength := int(data[pos])
	pos += 1 + sessionIDLength
	if pos >= len(data) {
		return "", fmt.Errorf("handshake too short for cipher suites")
	}

	// Skip cipher suites
	cipherSuitesLength := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLength
	if pos >= len(data) {
		return "", fmt.Errorf("handshake too short for compression methods")
	}

	// Skip compression methods
	compressionMethodsLength := int(data[pos])
	pos += 1 + compressionMethodsLength
	if pos >= len(data) {
		return "", fmt.Errorf("handshake too short for extensions")
	}

	// Parse extensions
	if pos+2 > len(data) {
		return "", fmt.Errorf("no extensions present")
	}
	extensionsLength := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	extensionsEnd := pos + extensionsLength

	// Iterate through extensions
	for pos+4 <= extensionsEnd {
		extensionType := int(data[pos])<<8 | int(data[pos+1])
		extensionLength := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extensionType == TLSExtServerName {
			if pos+2 > len(data) {
				return "", fmt.Errorf("SNI extension too short")
			}
			sniListLength := int(data[pos])<<8 | int(data[pos+1])
			pos += 2

			if pos+sniListLength > len(data) {
				return "", fmt.Errorf("SNI list too short")
			}

			// Read SNI entries
			sniEnd := pos + sniListLength
			for pos+3 <= sniEnd {
				sniType := data[pos]
				sniLength := int(data[pos+1])<<8 | int(data[pos+2])
				pos += 3

				if sniType == 0 { // Host name
					if pos+sniLength > len(data) {
						return "", fmt.Errorf("SNI hostname too short")
					}
					return string(data[pos : pos+sniLength]), nil
				}
				pos += sniLength
			}
		}
		pos += extensionLength
	}

	return "", fmt.Errorf("no SNI extension found")
}

func shouldIgnore(session Session) bool {
	// If we haven't received any ignore patterns yet, don't ignore anything
	if !hasIgnorePatterns {
		return false
	}

	// Check each category independently and immediately return if any pattern matches

	// Check port patterns
	for _, pattern := range ignorePatterns {
		if pattern.Type == "port" {
			port, err := strconv.Atoi(pattern.Value)
			if err != nil {
				continue
			}
			if session.SourcePort == port || session.DestinationPort == port {
				ignoreStats.PacketCounts.Ports++
				return true
			}
		}
	}

	// Check IP patterns
	for _, pattern := range ignorePatterns {
		if pattern.Type == "ip" {
			if session.SourceIP == pattern.Value || session.DestinationIP == pattern.Value {
				ignoreStats.PacketCounts.IPs++
				return true
			}
		}
	}

	// Check IP pair patterns
	for _, pattern := range ignorePatterns {
		if pattern.Type == "pair" {
			if (session.SourceIP+":"+session.DestinationIP == pattern.Value) ||
				(session.DestinationIP+":"+session.SourceIP == pattern.Value) {
				ignoreStats.PacketCounts.IPPairs++
				return true
			}
		}
	}

	// Check DNS patterns
	for _, pattern := range ignorePatterns {
		if pattern.Type == "dns" && session.DNSQuery != "" {
			if strings.Contains(session.DNSQuery, pattern.Value) {
				ignoreStats.PacketCounts.DNSQueries++
				return true
			}
		}
	}

	// Check SNI patterns
	for _, pattern := range ignorePatterns {
		if pattern.Type == "sni" && session.SNI != "" {
			if strings.Contains(session.SNI, pattern.Value) {
				ignoreStats.PacketCounts.SNIHosts++
				return true
			}
		}
	}

	return false
}
