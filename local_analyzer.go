package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/nlpodyssey/spago/mat"
	"github.com/nlpodyssey/spago/nn/transformer/bert"
)

// LocalAnalyzer implements the Analyzer interface using local BERT models
type LocalAnalyzer struct {
	modelPath string
	debug     bool
	model     *bert.Model
}

// NewLocalAnalyzer creates a new instance of LocalAnalyzer
func NewLocalAnalyzer(modelPath string) (*LocalAnalyzer, error) {
	// Load the BERT model
	model, err := bert.LoadModel(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load BERT model: %v", err)
	}

	return &LocalAnalyzer{
		modelPath: modelPath,
		debug:     false,
		model:     model,
	}, nil
}

// StartAnalysis begins the analysis process
func (a *LocalAnalyzer) StartAnalysis(rollupChan <-chan NetworkRollup) {
	for rollup := range rollupChan {
		a.ProcessRollup(rollup)
	}
}

// ProcessRollup handles a single rollup of network data
func (a *LocalAnalyzer) ProcessRollup(rollup NetworkRollup) {
	// Convert network data to text format for analysis
	text := a.convertRollupToText(rollup)

	// Process with BERT model
	analysis := a.analyzeWithLocalModel(text)

	// Log the analysis results
	log.Printf("Local analysis results: %s", analysis)
}

// GetAnalysisType returns the type of analyzer
func (a *LocalAnalyzer) GetAnalysisType() string {
	return "local"
}

// Helper functions for local model processing
func (a *LocalAnalyzer) convertRollupToText(rollup NetworkRollup) string {
	var text strings.Builder

	// Add connection information
	text.WriteString("Network activity summary:\n")
	text.WriteString(fmt.Sprintf("Total connections: %d\n", len(rollup.Connections)))

	// Add connection details
	for _, conn := range rollup.Connections {
		text.WriteString(fmt.Sprintf("Connection: %s:%d <-> %s:%d (bytes: %d, duration: %s)\n",
			conn.Endpoint1, conn.Port1, conn.Endpoint2, conn.Port2,
			conn.Bytes, conn.LastSeen.Sub(conn.FirstSeen)))
	}

	// Add DNS information
	text.WriteString("\nDNS activity:\n")
	for _, dns := range rollup.DNSRecords {
		text.WriteString(fmt.Sprintf("DNS query: %s -> %s (type: %s, status: %s)\n",
			dns.Query, dns.Response, dns.Type, dns.Status))
	}

	// Add SNI information
	text.WriteString("\nTLS/SNI activity:\n")
	for _, sni := range rollup.SNIRecords {
		text.WriteString(fmt.Sprintf("SNI hostname: %s\n", sni.Hostname))
	}

	return text.String()
}

func (a *LocalAnalyzer) analyzeWithLocalModel(text string) string {
	// Split text into chunks to handle BERT's max sequence length
	chunks := splitTextIntoChunks(text, 512) // BERT typically handles 512 tokens
	var analysis strings.Builder

	analysis.WriteString("Analysis based on BERT embeddings:\n")

	for i, chunk := range chunks {
		analysis.WriteString(fmt.Sprintf("\nChunk %d analysis:\n", i+1))

		// Get embeddings from the BERT model
		embedding, err := a.model.Vectorize(chunk, bert.ReduceMean)
		if err != nil {
			log.Printf("Error getting embeddings for chunk %d: %v", i+1, err)
			continue
		}

		// Analyze the embeddings
		analysis.WriteString(a.analyzeEmbedding(embedding))

		// Perform sequence classification if available
		if classificationResult := a.performSequenceClassification(chunk); classificationResult != "" {
			analysis.WriteString(classificationResult)
		}
	}

	return analysis.String()
}

func (a *LocalAnalyzer) analyzeEmbedding(embedding mat.Matrix) string {
	var analysis strings.Builder

	// Calculate statistical measures
	maxVal := mat.Max(embedding)
	minVal := mat.Min(embedding)
	avgVal := mat.Mean(embedding)
	stdDev := mat.StdDev(embedding)
	variance := mat.Variance(embedding)

	// Define thresholds for anomaly detection
	const (
		highStdDevThreshold = 2.0
		highVarThreshold    = 4.0
	)

	analysis.WriteString(fmt.Sprintf("Embedding statistics:\n"))
	analysis.WriteString(fmt.Sprintf("- Max value: %.4f\n", maxVal))
	analysis.WriteString(fmt.Sprintf("- Min value: %.4f\n", minVal))
	analysis.WriteString(fmt.Sprintf("- Average value: %.4f\n", avgVal))
	analysis.WriteString(fmt.Sprintf("- Standard deviation: %.4f\n", stdDev))
	analysis.WriteString(fmt.Sprintf("- Variance: %.4f\n", variance))

	// Flag potential anomalies
	if stdDev > highStdDevThreshold {
		analysis.WriteString("⚠️ High standard deviation detected - possible anomalous activity\n")
	}
	if variance > highVarThreshold {
		analysis.WriteString("⚠️ High variance detected - possible unusual network patterns\n")
	}

	return analysis.String()
}

func (a *LocalAnalyzer) performSequenceClassification(text string) string {
	if a.model.Classifier == nil {
		return ""
	}

	// Encode the text
	encoded := a.model.Encode(strings.Split(text, " "))

	// Perform classification
	result := a.model.SequenceClassification(encoded)
	if result == nil {
		return ""
	}

	// Get the classification result
	classification := result.Value()
	if classification == nil {
		return ""
	}

	return fmt.Sprintf("\nSequence Classification:\n- Score: %.4f\n", classification.Item())
}

// Helper function to split text into chunks that BERT can handle
func splitTextIntoChunks(text string, maxTokens int) []string {
	words := strings.Split(text, " ")
	var chunks []string
	var currentChunk []string
	currentLength := 0

	for _, word := range words {
		// Rough estimation: 1 word ≈ 1.5 tokens on average
		wordTokens := len(word)/2 + 1
		if currentLength+wordTokens > maxTokens && len(currentChunk) > 0 {
			chunks = append(chunks, strings.Join(currentChunk, " "))
			currentChunk = []string{word}
			currentLength = wordTokens
		} else {
			currentChunk = append(currentChunk, word)
			currentLength += wordTokens
		}
	}

	if len(currentChunk) > 0 {
		chunks = append(chunks, strings.Join(currentChunk, " "))
	}

	return chunks
}
