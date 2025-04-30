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

var (
	interfaceName = flag.String("i", "", "Network interface to monitor")
	apiKey        = flag.String("k", "", "OpenAI API key")
	debugMode     = flag.Bool("debug", false, "Enable debug mode for verbose output")
	debugAIMode   = flag.Bool("debug-ai", false, "Enable AI conversation debugging")
	sessions      = make(map[string]Session)
	sessionMutex  = &sync.RWMutex{}
	logger        = logrus.New()
	aiSessionID   string
	chatHistory   []map[string]string
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

	// Check for TLS/SNI
	if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
		if *debugMode {
			logger.Debug("TLS packet detected")
		}
		session.Protocol = "TLS"
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
				session.DNSQuery = query
				if *debugMode {
					logger.Debugf("Extracted DNS query: %s", query)
				}
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

	logger.Infof("\n=== Session Statistics ===")
	logger.Infof("Total Sessions: %d", len(snapshot.Sessions))
	logger.Infof("SNI Count: %d", sniCount)
	logger.Infof("DNS Query Count: %d", dnsCount)
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
1. "IGNORE": typical patterns with source/destination pairs
2. anomalies: unusual patterns with session counts and bytes, this something you will track with context because it might not be serious now but worth nothing and watching.
3. "BAD": malicious activity with session counts and bytes

We will be sending you a snapshot of DNS, SNI, and sessions tables every 30 seconds so keep this history and build context on it.

Respond in this exact JSON format:
{
    "IGNORE": [{"description": "pattern", "details": [{"source": "ip", "destination": "ip"}]}],
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

	// Clean up the response by removing markdown code blocks if present
	cleanResponse := aiResponse
	if strings.Contains(cleanResponse, "```json") {
		cleanResponse = strings.TrimPrefix(cleanResponse, "```json")
		cleanResponse = strings.TrimSuffix(cleanResponse, "```")
		cleanResponse = strings.TrimSpace(cleanResponse)
	}

	// Parse the AI response
	var analysis AIAnalysis
	if err := json.Unmarshal([]byte(cleanResponse), &analysis); err != nil {
		logger.Errorf("Error parsing AI response: %v", err)
		return
	}

	// Create a map of sessions to keep
	sessionsToKeep := make(map[string]bool)

	// Mark sessions to keep based on AI analysis
	for _, bad := range analysis.Bad {
		key := fmt.Sprintf("%s:%s", bad.Details.Source, bad.Details.Destination)
		sessionsToKeep[key] = true
	}

	// Prune uninteresting sessions
	for key := range sessions {
		if !sessionsToKeep[key] {
			// Check if this session is marked as normal
			isNormal := false
			for _, ignore := range analysis.Ignore {
				for _, detail := range ignore.Details {
					normalKey := fmt.Sprintf("%s:%s", detail.Source, detail.Destination)
					if normalKey == key {
						isNormal = true
						break
					}
				}
				if isNormal {
					break
				}
			}
			if isNormal {
				delete(sessions, key)
			}
		}
	}

	// Also remove sessions older than 5 minutes
	now := time.Now()
	for key, session := range sessions {
		if now.Sub(session.LastSeen) > 5*time.Minute {
			delete(sessions, key)
		}
	}

	logger.Info("\n=== Session Pruning Results ===")
	logger.Infof("Original session count: %d", originalCount)
	logger.Infof("Current session count: %d", len(sessions))
	logger.Infof("Sessions pruned: %d", originalCount-len(sessions))

	// Log AI's categorization
	logger.Info("\nAI Analysis Summary:")
	logger.Infof("Summary: %s", analysis.Summary)
	logger.Infof("Ignored traffic groups: %d", len(analysis.Ignore))
	logger.Infof("Bad sessions: %d", len(analysis.Bad))

	// Log some example reasons
	if len(analysis.Ignore) > 0 {
		logger.Info("\nExample ignored traffic:")
		for i := 0; i < min(3, len(analysis.Ignore)); i++ {
			logger.Infof("- %s", analysis.Ignore[i].Description)
			for j := 0; j < min(3, len(analysis.Ignore[i].Details)); j++ {
				logger.Infof("  • %s -> %s",
					analysis.Ignore[i].Details[j].Source,
					analysis.Ignore[i].Details[j].Destination)
			}
		}
	}
	if len(analysis.Bad) > 0 {
		logger.Info("\nExample bad sessions:")
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
	header := fmt.Sprintf("%-20s %-10s %-20s %-10s %-8s %-8s %-12s %-12s %-12s",
		"Source", "SrcPort", "Destination", "DstPort", "Proto", "Sessions", "Avg Bytes", "Total Bytes", "Duration")
	separator := strings.Repeat("-", len(header))

	builder.WriteString(header + "\n")
	builder.WriteString(separator + "\n")

	// Sort sessions by total bytes (descending)
	sort.Slice(compressedSessions, func(i, j int) bool {
		return compressedSessions[i].TotalBytes > compressedSessions[j].TotalBytes
	})

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

		row := fmt.Sprintf("%-20s %-10s %-20s %-10d %-8s %-8d %-12s %-12s %-12s",
			session.SourceIP,
			srcPort,
			session.DestinationIP,
			session.DestinationPort,
			session.Protocol,
			session.Count,
			avgBytesStr,
			totalBytesStr,
			durationStr)

		builder.WriteString(row + "\n")
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
