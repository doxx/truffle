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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

type Session struct {
	SourceIP      string
	DestinationIP string
	Protocol      string
	Port          int
	SNI           string
	DNSQuery      string
	LastSeen      time.Time
}

type NetworkSnapshot struct {
	Sessions   []Session
	SNIs       []string
	DNSQueries []string
	Timestamp  time.Time
}

var (
	interfaceName = flag.String("i", "", "Network interface to monitor")
	apiKey        = flag.String("k", "", "OpenAI API key")
	debugMode     = flag.Bool("debug", false, "Enable debug mode for verbose output")
	sessions      = make(map[string]Session)
	snapshotChan  = make(chan NetworkSnapshot)
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
	if *debugMode {
		logger.SetLevel(logrus.DebugLevel)
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.Info("Starting Truffle network monitor")
	logger.Infof("Monitoring interface: %s", *interfaceName)
	if *debugMode {
		logger.Debug("Debug mode enabled")
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start packet capture
	go capturePackets(*interfaceName)

	// Start snapshot timer
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-ticker.C:
				sendSnapshot()
			case <-sigChan:
				ticker.Stop()
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

	// Create session key
	portStr := transportLayer.TransportFlow().Dst().String()
	port, err := strconv.Atoi(portStr)
	if err != nil {
		if *debugMode {
			logger.Debugf("Error converting port %s to integer: %v", portStr, err)
		}
		return
	}

	sessionKey := fmt.Sprintf("%s:%s:%d",
		networkLayer.NetworkFlow().Src().String(),
		networkLayer.NetworkFlow().Dst().String(),
		port)

	// Update or create session
	session := Session{
		SourceIP:      networkLayer.NetworkFlow().Src().String(),
		DestinationIP: networkLayer.NetworkFlow().Dst().String(),
		Protocol:      transportLayer.LayerType().String(),
		Port:          port,
		LastSeen:      time.Now(),
	}

	// Check for TLS/SNI
	if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
		if *debugMode {
			logger.Debug("TLS packet detected")
		}
		// For now, we'll just note that TLS traffic was detected
		// A more sophisticated SNI extraction would require implementing
		// a proper TLS handshake parser
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
}

type OpenAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func sendSnapshot() {
	snapshot := NetworkSnapshot{
		Timestamp: time.Now(),
	}

	// Convert sessions map to slice
	for _, session := range sessions {
		snapshot.Sessions = append(snapshot.Sessions, session)
	}

	if *debugMode {
		logger.Debugf("Preparing snapshot with %d sessions", len(snapshot.Sessions))
		logger.Debugf("Session table state: %+v", sessions)
	}

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
		logger.Debug("Sending prompt to OpenAI API")
		logger.Debugf("Prompt: %s", prompt)
	}

	// Prepare OpenAI API request
	requestBody := map[string]interface{}{
		"model": "gpt-4",
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
		logger.Errorf("Error marshaling request: %v", err)
		return
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Errorf("Error creating request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("Error sending request: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Error reading response: %v", err)
		return
	}

	if *debugMode {
		logger.Debugf("OpenAI API Response: %s", string(body))
	}

	var openAIResp OpenAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		logger.Errorf("Error parsing response: %v", err)
		return
	}

	if len(openAIResp.Choices) > 0 {
		response := openAIResp.Choices[0].Message.Content
		if *debugMode {
			logger.Debugf("AI Analysis: %s", response)
		}
		// TODO: Process AI response to update monitoring rules
	}
}

func formatSnapshot(snapshot NetworkSnapshot) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Timestamp: %s\n", snapshot.Timestamp.Format(time.RFC3339)))
	builder.WriteString("\nSessions:\n")
	for _, session := range snapshot.Sessions {
		builder.WriteString(fmt.Sprintf("- %s -> %s:%d (%s)\n",
			session.SourceIP,
			session.DestinationIP,
			session.Port,
			session.Protocol))
	}
	if len(snapshot.SNIs) > 0 {
		builder.WriteString("\nSNIs:\n")
		for _, sni := range snapshot.SNIs {
			builder.WriteString(fmt.Sprintf("- %s\n", sni))
		}
	}
	if len(snapshot.DNSQueries) > 0 {
		builder.WriteString("\nDNS Queries:\n")
		for _, query := range snapshot.DNSQueries {
			builder.WriteString(fmt.Sprintf("- %s\n", query))
		}
	}
	return builder.String()
}
