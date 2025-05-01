package main

import "time"

// NetworkRollup represents a rollup of network data
type NetworkRollup struct {
	Timestamp   time.Time
	Connections []Connection
	DNSRecords  []DNSRecord
	SNIRecords  []SNIRecord
}

// Connection represents a network connection between two endpoints
type Connection struct {
	Endpoint1        string
	Port1            uint16
	Port1IsEphemeral bool
	Endpoint2        string
	Port2            uint16
	Port2IsEphemeral bool
	Count            int
	Bytes            int64
	FirstSeen        time.Time
	LastSeen         time.Time
}

// DNSRecord represents a DNS query/response
type DNSRecord struct {
	Query     string
	Response  string
	Type      string // Type of response (A, AAAA, NXDOMAIN, etc.)
	Status    string // DNS response status (NOERROR, NXDOMAIN, etc.)
	FirstSeen time.Time
	LastSeen  time.Time
}

// SNIRecord represents a TLS SNI record
type SNIRecord struct {
	Hostname  string
	FirstSeen time.Time
	LastSeen  time.Time
}
