package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Filter represents a single filter rule
type Filter struct {
	Rule   string
	Reason string
	TTL    int
	Expiry time.Time
}

// FilterManager manages all active filters
type FilterManager struct {
	filters map[string]*Filter
	mu      sync.RWMutex
}

// NewFilterManager creates a new filter manager
func NewFilterManager() *FilterManager {
	return &FilterManager{
		filters: make(map[string]*Filter),
	}
}

// AddFilter adds a new filter to the manager
func (fm *FilterManager) AddFilter(rule, reason string, ttl int) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	filter := &Filter{
		Rule:   rule,
		Reason: reason,
		TTL:    ttl,
		Expiry: time.Now().Add(time.Duration(ttl) * time.Minute),
	}

	fm.filters[rule] = filter
}

// RemoveExpiredFilters removes filters that have expired
func (fm *FilterManager) RemoveExpiredFilters() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	now := time.Now()
	for rule, filter := range fm.filters {
		if now.After(filter.Expiry) {
			delete(fm.filters, rule)
		}
	}
}

// ShouldFilter checks if a given item should be filtered based on the active filters
func (fm *FilterManager) ShouldFilter(item interface{}) bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	for _, filter := range fm.filters {
		if matchesFilter(item, filter.Rule) {
			return true
		}
	}
	return false
}

// matchesFilter checks if an item matches a filter rule
func matchesFilter(item interface{}, rule string) bool {
	// Split the rule into individual conditions
	conditions := strings.Split(rule, " AND ")
	if len(conditions) > 1 {
		// All conditions must match for AND
		for _, condition := range conditions {
			if !matchesSingleCondition(item, condition) {
				return false
			}
		}
		return true
	}

	// Check for OR conditions
	conditions = strings.Split(rule, " OR ")
	if len(conditions) > 1 {
		// Any condition can match for OR
		for _, condition := range conditions {
			if matchesSingleCondition(item, condition) {
				return true
			}
		}
		return false
	}

	// Single condition
	return matchesSingleCondition(item, rule)
}

// matchesSingleCondition checks if an item matches a single filter condition
func matchesSingleCondition(item interface{}, condition string) bool {
	// Parse the condition type and value
	parts := strings.SplitN(condition, ":", 2)
	if len(parts) != 2 {
		return false
	}

	conditionType := parts[0]
	conditionValue := parts[1]

	switch conditionType {
	case "ip":
		if ip, ok := item.(string); ok {
			return ip == conditionValue
		}
	case "port":
		if port, ok := item.(uint16); ok {
			return fmt.Sprintf("%d", port) == conditionValue
		}
	case "dns":
		if domain, ok := item.(string); ok {
			// Convert wildcard pattern to regex pattern
			pattern := strings.ReplaceAll(conditionValue, "*", ".*")
			// Ensure we match the entire domain
			pattern = "^" + pattern + "$"
			// Escape dots in the pattern
			pattern = strings.ReplaceAll(pattern, ".", "\\.")
			// Convert wildcards back
			pattern = strings.ReplaceAll(pattern, "\\*", ".*")
			matched, _ := regexp.MatchString(pattern, domain)
			return matched
		}
	case "sni":
		if hostname, ok := item.(string); ok {
			// Convert wildcard pattern to regex pattern
			pattern := strings.ReplaceAll(conditionValue, "*", ".*")
			// Ensure we match the entire hostname
			pattern = "^" + pattern + "$"
			// Escape dots in the pattern
			pattern = strings.ReplaceAll(pattern, ".", "\\.")
			// Convert wildcards back
			pattern = strings.ReplaceAll(pattern, "\\*", ".*")
			matched, _ := regexp.MatchString(pattern, hostname)
			return matched
		}
	case "proto":
		if protocol, ok := item.(string); ok {
			return strings.EqualFold(protocol, conditionValue)
		}
	}
	return false
}

// ApplyFilters applies all active filters to a NetworkRollup
func (fm *FilterManager) ApplyFilters(rollup *NetworkRollup) {
	fm.RemoveExpiredFilters()

	// Log active filters
	fm.mu.RLock()
	log.Printf("Active filters: %d", len(fm.filters))
	for _, filter := range fm.filters {
		log.Printf("Filter: %s (TTL: %d minutes remaining)", filter.Rule, int(time.Until(filter.Expiry).Minutes()))
	}
	fm.mu.RUnlock()

	originalCount := len(rollup.Connections)
	// Filter connections
	filteredConnections := make([]Connection, 0)
	for _, conn := range rollup.Connections {
		if !fm.ShouldFilter(conn.Endpoint1) && !fm.ShouldFilter(conn.Endpoint2) &&
			!fm.ShouldFilter(conn.Port1) && !fm.ShouldFilter(conn.Port2) {
			filteredConnections = append(filteredConnections, conn)
		}
	}
	rollup.Connections = filteredConnections
	log.Printf("Filtered connections: %d -> %d", originalCount, len(rollup.Connections))

	originalCount = len(rollup.DNSRecords)
	// Filter DNS records
	filteredDNS := make([]DNSRecord, 0)
	for _, dns := range rollup.DNSRecords {
		if !fm.ShouldFilter(dns.Query) {
			filteredDNS = append(filteredDNS, dns)
		} else {
			log.Printf("Filtered DNS query: %s", dns.Query)
		}
	}
	rollup.DNSRecords = filteredDNS
	log.Printf("Filtered DNS records: %d -> %d", originalCount, len(rollup.DNSRecords))

	originalCount = len(rollup.SNIRecords)
	// Filter SNI records
	filteredSNI := make([]SNIRecord, 0)
	for _, sni := range rollup.SNIRecords {
		if !fm.ShouldFilter(sni.Hostname) {
			filteredSNI = append(filteredSNI, sni)
		} else {
			log.Printf("Filtered SNI hostname: %s", sni.Hostname)
		}
	}
	rollup.SNIRecords = filteredSNI
	log.Printf("Filtered SNI records: %d -> %d", originalCount, len(rollup.SNIRecords))
}
