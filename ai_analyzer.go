package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AISession represents the state of our AI analysis session
type AISession struct {
	apiKey        string
	chatHistory   []map[string]string
	mu            sync.RWMutex
	lastPrompt    time.Time
	promptCounter int
	filterManager *FilterManager
	debug         bool
	// Token tracking
	tokenUsage     int
	lastTokenReset time.Time
	rateLimiter    *RateLimiter
}

// AIResponse represents the AI's analysis of our network data
type AIResponse struct {
	Filters []struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
		TTL    int    `json:"ttl"` // Time to live in minutes
	} `json:"filters"`
	Anomalies []struct {
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Evidence    string `json:"evidence"`
	} `json:"anomalies"`
	Summary string `json:"summary"`
}

// RateLimiter tracks token usage and enforces rate limits
type RateLimiter struct {
	mu            sync.Mutex
	tokenLimit    int
	tokenUsage    int
	lastReset     time.Time
	resetInterval time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(tokenLimit int, resetInterval time.Duration) *RateLimiter {
	return &RateLimiter{
		tokenLimit:    tokenLimit,
		resetInterval: resetInterval,
		lastReset:     time.Now(),
	}
}

// CanProceed checks if we can make another request based on token limits
func (rl *RateLimiter) CanProceed(estimatedTokens int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Reset token count if interval has passed
	if time.Since(rl.lastReset) >= rl.resetInterval {
		rl.tokenUsage = 0
		rl.lastReset = time.Now()
	}

	// Check if we have enough tokens remaining
	return rl.tokenUsage+estimatedTokens <= rl.tokenLimit
}

// UpdateUsage updates the token usage
func (rl *RateLimiter) UpdateUsage(tokens int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.tokenUsage += tokens
}

// GetWaitTime returns how long to wait before next request
func (rl *RateLimiter) GetWaitTime(estimatedTokens int) time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// If we can proceed immediately, return 0
	if rl.tokenUsage+estimatedTokens <= rl.tokenLimit {
		return 0
	}

	// Calculate time until next reset
	nextReset := rl.lastReset.Add(rl.resetInterval)
	return time.Until(nextReset)
}

// NewAISession creates a new AI analysis session
func NewAISession(apiKey string, debug bool) *AISession {
	return &AISession{
		apiKey:        apiKey,
		chatHistory:   make([]map[string]string, 0),
		filterManager: NewFilterManager(debug),
		debug:         debug,
	}
}

// StartAnalysis starts the AI analysis loop
func (s *AISession) StartAnalysis(rollupChan <-chan NetworkRollup) {
	go s.analysisLoop(rollupChan)
}

// analysisLoop processes rollups and sends them to the AI
func (s *AISession) analysisLoop(rollupChan <-chan NetworkRollup) {
	for rollup := range rollupChan {
		// Process the rollup asynchronously
		go s.processRollup(rollup)
	}
}

// processRollup handles a single rollup of network data
func (s *AISession) processRollup(rollup NetworkRollup) {
	// Apply filters before formatting
	s.filterManager.ApplyFilters(&rollup)

	// Format the rollup data
	formattedData := s.formatRollup(rollup)

	// Check if we need to send the system prompt
	s.mu.Lock()
	if len(s.chatHistory) == 0 || s.promptCounter >= 10 {
		s.sendSystemPrompt()
		s.promptCounter = 0
	}
	s.mu.Unlock()

	// Send to OpenAI and get response
	response, err := s.sendToOpenAI(formattedData)
	if err != nil {
		log.Printf("Error sending to OpenAI: %v", err)
		return
	}

	// Process the response
	s.processResponse(response)
}

// formatRollup formats the network data for the AI
func (s *AISession) formatRollup(rollup NetworkRollup) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Network Snapshot at %s\n\n", rollup.Timestamp)

	// Connection Statistics
	totalConnections := len(rollup.Connections)
	totalBytes := int64(0)
	portStats := make(map[uint16]int)
	ipStats := make(map[string]int)

	fmt.Fprintf(&buf, "=== Connection Statistics ===\n")
	fmt.Fprintf(&buf, "Total Active Connections: %d\n\n", totalConnections)

	fmt.Fprintln(&buf, "Active Connections:")
	for _, conn := range rollup.Connections {
		// Update statistics
		totalBytes += conn.Bytes
		portStats[conn.Port1]++
		portStats[conn.Port2]++
		ipStats[conn.Endpoint1]++
		ipStats[conn.Endpoint2]++

		// Format connection
		port1 := fmt.Sprintf("%d", conn.Port1)
		if conn.Port1IsEphemeral {
			port1 = "ephemeral"
		}
		port2 := fmt.Sprintf("%d", conn.Port2)
		if conn.Port2IsEphemeral {
			port2 = "ephemeral"
		}

		fmt.Fprintf(&buf, "- %s:%s <-> %s:%s (count: %d, bytes: %d, duration: %s)\n",
			conn.Endpoint1, port1, conn.Endpoint2, port2,
			conn.Count, conn.Bytes, conn.LastSeen.Sub(conn.FirstSeen))
	}

	// Port Statistics
	fmt.Fprintln(&buf, "\nPort Statistics:")
	for port, count := range portStats {
		if count > 1 { // Only show ports with multiple connections
			fmt.Fprintf(&buf, "- Port %d: %d connections\n", port, count)
		}
	}

	// IP Statistics
	fmt.Fprintln(&buf, "\nIP Statistics:")
	for ip, count := range ipStats {
		if count > 1 { // Only show IPs with multiple connections
			fmt.Fprintf(&buf, "- IP %s: %d connections\n", ip, count)
		}
	}

	// DNS Activity
	fmt.Fprintln(&buf, "\n=== DNS Activity ===")
	for _, dns := range rollup.DNSRecords {
		fmt.Fprintf(&buf, "- Query: %s -> Response: %s (first seen: %s, last seen: %s)\n",
			dns.Query, dns.Response,
			dns.FirstSeen.Format(time.RFC3339),
			dns.LastSeen.Format(time.RFC3339))
	}

	// SNI Activity
	fmt.Fprintln(&buf, "\n=== SNI Activity ===")
	for _, sni := range rollup.SNIRecords {
		fmt.Fprintf(&buf, "- Hostname: %s (first seen: %s, last seen: %s)\n",
			sni.Hostname,
			sni.FirstSeen.Format(time.RFC3339),
			sni.LastSeen.Format(time.RFC3339))
	}

	// Summary Statistics
	fmt.Fprintf(&buf, "\n=== Summary ===\n")
	fmt.Fprintf(&buf, "Total Connections: %d\n", totalConnections)
	fmt.Fprintf(&buf, "Total Bytes: %d\n", totalBytes)
	fmt.Fprintf(&buf, "Unique IPs: %d\n", len(ipStats))
	fmt.Fprintf(&buf, "Unique Ports: %d\n", len(portStats))
	fmt.Fprintf(&buf, "DNS Queries: %d\n", len(rollup.DNSRecords))
	fmt.Fprintf(&buf, "SNI Hostnames: %d\n", len(rollup.SNIRecords))

	return buf.String()
}

// sendSystemPrompt sends the initial system prompt to OpenAI
func (s *AISession) sendSystemPrompt() {
	systemPrompt := `You are a network security expert analyzing network traffic patterns in real-time.
Your task is to identify normal patterns, anomalies, and potential security concerns.

You will receive network data in the following format:
1. Connection statistics (IPs, ports, bytes, duration)
2. DNS queries and responses
3. SNI (Server Name Indication) hostnames from TLS connections

Your job is to:
1. Identify baseline traffic patterns
2. Detect anomalies and potential threats
3. Suggest data filters to reduce noise in future analysis cycles
4. Provide evidence for your decisions
5. Maintain context across analysis cycles

Note: With the summary provide to and from IP addresses and ports that might be related to the issue. For example if it's a bad dns host, what host did that query.

Data Filter Format:
Use a simple filter language that can match:
- IP addresses (e.g., "ip:192.168.1.1")
- Ports (e.g., "port:443")
- DNS domains (e.g., "dns:*.google.com")
- SNI hostnames (e.g., "sni:*.cloudflare.com")
- Protocols (e.g., "proto:tcp")

Filters can be combined with AND/OR:
- "ip:192.168.1.1 AND port:443"
- "dns:*.google.com OR dns:*.youtube.com"
- "sni:*.cloudflare.com AND proto:tcp"

Each filter should include:
1. The filter rule
2. A reason for the filter
3. A TTL (time to live) in minutes

Example filters:
- "ip:192.168.1.1 AND port:443" - "Normal HTTPS traffic to internal server" - TTL: 60
- "dns:*.google.com" - "Common DNS queries to Google services" - TTL: 30
- "sni:*.cloudflare.com" - "Expected CDN traffic" - TTL: 45

Response Format:
{
    "filters": [
        {
            "rule": "ip:192.168.1.1 AND port:443",
            "reason": "Normal HTTPS traffic to internal server",
            "ttl": 60
        }
    ],
    "anomalies": [
        {
            "description": "Unusual port scanning pattern",
            "severity": "high",
            "evidence": "Multiple connection attempts to different ports from same source"
        }
    ],
    "summary": "Overall analysis summary"
}`

	s.chatHistory = []map[string]string{
		{
			"role":    "system",
			"content": systemPrompt,
		},
	}
}

// sendToOpenAI sends data to OpenAI and gets a response
func (s *AISession) sendToOpenAI(data string) (*AIResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Add the user's message to chat history
	s.chatHistory = append(s.chatHistory, map[string]string{
		"role":    "user",
		"content": data,
	})

	// Prepare the request
	requestBody := map[string]interface{}{
		"model":    "gpt-4o",
		"messages": s.chatHistory,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %v", err)
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Log the raw response for debugging
	if s.debug {
		log.Printf("OpenAI Response Status: %d", resp.StatusCode)
		log.Printf("OpenAI Response Body: %s", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API returned status %d: %s", resp.StatusCode, string(body))
	}

	var openAIResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return nil, fmt.Errorf("error parsing OpenAI response: %v", err)
	}

	if openAIResp.Error.Message != "" {
		return nil, fmt.Errorf("OpenAI API error: %s", openAIResp.Error.Message)
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in OpenAI response")
	}

	// Parse the AI's response into our structured format
	var aiResponse AIResponse
	content := openAIResp.Choices[0].Message.Content

	// Remove markdown code block formatting if present
	if strings.HasPrefix(content, "```json") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)
	}

	// Validate JSON structure
	if !json.Valid([]byte(content)) {
		// Try to fix common JSON issues
		content = strings.ReplaceAll(content, ",\n}", "\n}")
		content = strings.ReplaceAll(content, ",}", "}")
		content = strings.ReplaceAll(content, ",\n]", "\n]")
		content = strings.ReplaceAll(content, ",]", "]")
	}

	if err := json.Unmarshal([]byte(content), &aiResponse); err != nil {
		log.Printf("Failed to parse content: %s", content)
		return nil, fmt.Errorf("error parsing AI response content: %v", err)
	}

	// Validate the parsed response
	if len(aiResponse.Filters) == 0 && len(aiResponse.Anomalies) == 0 {
		return nil, fmt.Errorf("empty response from AI")
	}

	// Add the AI's response to chat history
	s.chatHistory = append(s.chatHistory, map[string]string{
		"role":    "assistant",
		"content": openAIResp.Choices[0].Message.Content,
	})

	s.promptCounter++

	return &aiResponse, nil
}

// processResponse handles the AI's response and applies filters
func (s *AISession) processResponse(response *AIResponse) {
	// Always show the AI analysis summary
	log.Printf("\n=== AI Analysis ===")
	if len(response.Anomalies) > 0 {
		log.Printf("\nAnomalies:")
		for _, anomaly := range response.Anomalies {
			log.Printf("- %s (Severity: %s)\n  Evidence: %s",
				anomaly.Description, anomaly.Severity, anomaly.Evidence)
		}
	} else {
		log.Printf("\nNo anomalies detected")
	}
	log.Printf("\nSummary: %s", response.Summary)
	log.Printf("==================\n")

	// Only show filter details in debug mode
	if s.debug {
		log.Printf("Filters:")
		for _, filter := range response.Filters {
			log.Printf("- %s (TTL: %d minutes)\n  Reason: %s",
				filter.Rule, filter.TTL, filter.Reason)
		}
	}

	// Add filters to filter manager regardless of debug mode
	for _, filter := range response.Filters {
		s.filterManager.AddFilter(filter.Rule, filter.Reason, filter.TTL)
	}
}
