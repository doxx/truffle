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
	Uninteresting []struct {
		Source      string   `json:"source"`
		Destination []string `json:"destination"`
		Description string   `json:"description"`
	} `json:"uninteresting"`
	Anomalies []struct {
		Source      string   `json:"source"`
		Destination []string `json:"destination"`
		Description string   `json:"description"`
	} `json:"anomalies"`
	Bad []struct {
		Source      string   `json:"source"`
		Destination []string `json:"destination"`
		Description string   `json:"description"`
	} `json:"bad"`
}

type OpenAIResponse struct {
	Choices []struct {
		Message struct {
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

	// Create session key
	sessionKey := fmt.Sprintf("%s:%d:%s:%d",
		networkLayer.NetworkFlow().Src().String(),
		srcPort,
		networkLayer.NetworkFlow().Dst().String(),
		dstPort)

	// Update or create session
	sessionMutex.Lock()
	session, exists := sessions[sessionKey]
	if !exists {
		session = Session{
			SourceIP:        networkLayer.NetworkFlow().Src().String(),
			SourcePort:      srcPort,
			DestinationIP:   networkLayer.NetworkFlow().Dst().String(),
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
	if networkLayer.NetworkFlow().Src().String() == session.SourceIP {
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
		// Ignore source port for ephemeral ports
		key := fmt.Sprintf("%s:%s:%d",
			session.SourceIP,
			session.DestinationIP,
			session.DestinationPort)

		compressedSession, exists := compressed[key]
		if !exists {
			compressedSession = CompressedSession{
				SourceIP:        session.SourceIP,
				SourcePort:      0, // 0 indicates ephemeral
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
	prompt := fmt.Sprintf(`You are a network security expert analyzing a 30-second snapshot of network sessions, SNI captures, and DNS from a network interface. 
 
This is part of an ongoing monitoring system where we send you regular snapshots to help identify potential security threats. We will keep this session consistent so we can allow you to have context to determine what's happening.
Your task is to:
1. Identify things that appear completely normal and can be safely ignored (uninteresting)
2. Identify anything that shows potential security concerns for you to continue to track but don't freak out about them (anomalies)
3. Identify really bad stuff over time or actively (bad)

For each session, consider:
- usage and protocol patterns
- Large traffic volume and patterns to dangerous places
- SNI hosts that are bad or missing
- DNS hosts that are bad
- IPs that are bad
- Source and destination relationships

We will use your response to:
- Remove uninteresting sessions from our monitoring
- Focus our attention on bad things
- Track the evolution of suspicious patterns over time

Current snapshot data:
%s

Respond in JSON please`, formatSnapshot(snapshot))

	if *debugMode {
		printDebugInfo(snapshot, "Sending request to OpenAI API...")
	}

	if *debugAIMode {
		logger.Info("\n=== Sending to OpenAI API ===")
		logger.Info("Prompt:")
		logger.Info(prompt)
		logger.Info("===========================\n")
	}

	// Prepare OpenAI API request
	requestBody := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a network security expert analyzing network traffic patterns.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
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
		logger.Info("\n=== OpenAI API Response ===")
		logger.Info(string(body))
		logger.Info("=========================\n")
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
	for _, anomaly := range analysis.Anomalies {
		for _, dest := range anomaly.Destination {
			key := fmt.Sprintf("%s:%s", anomaly.Source, dest)
			sessionsToKeep[key] = true
		}
	}
	for _, bad := range analysis.Bad {
		for _, dest := range bad.Destination {
			key := fmt.Sprintf("%s:%s", bad.Source, dest)
			sessionsToKeep[key] = true
		}
	}

	// Prune uninteresting sessions
	for key := range sessions {
		if !sessionsToKeep[key] {
			// Check if this session is marked as uninteresting
			isUninteresting := false
			for _, uninteresting := range analysis.Uninteresting {
				if uninteresting.Source == strings.Split(key, ":")[0] {
					for _, dest := range uninteresting.Destination {
						if dest == strings.Split(key, ":")[1] {
							isUninteresting = true
							break
						}
					}
					if isUninteresting {
						break
					}
				}
			}
			if isUninteresting {
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
	logger.Infof("Uninteresting sessions: %d", len(analysis.Uninteresting))
	logger.Infof("Anomalous sessions: %d", len(analysis.Anomalies))
	logger.Infof("Bad sessions: %d", len(analysis.Bad))

	// Log some example reasons
	if len(analysis.Uninteresting) > 0 {
		logger.Info("\nExample uninteresting sessions:")
		for i := 0; i < min(3, len(analysis.Uninteresting)); i++ {
			logger.Infof("- %s -> %v: %s",
				analysis.Uninteresting[i].Source,
				analysis.Uninteresting[i].Destination,
				analysis.Uninteresting[i].Description)
		}
	}
	if len(analysis.Anomalies) > 0 {
		logger.Info("\nExample anomalous sessions:")
		for i := 0; i < min(3, len(analysis.Anomalies)); i++ {
			logger.Infof("- %s -> %v: %s",
				analysis.Anomalies[i].Source,
				analysis.Anomalies[i].Destination,
				analysis.Anomalies[i].Description)
		}
	}
	if len(analysis.Bad) > 0 {
		logger.Info("\nExample bad sessions:")
		for i := 0; i < min(3, len(analysis.Bad)); i++ {
			logger.Infof("- %s -> %v: %s",
				analysis.Bad[i].Source,
				analysis.Bad[i].Destination,
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
		srcPort := "ephemeral"
		if session.SourcePort != 0 {
			srcPort = fmt.Sprintf("%d", session.SourcePort)
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
