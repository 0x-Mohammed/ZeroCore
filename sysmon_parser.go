// ZeroCore Agent — Sysmon Event Parser
// Reads Sysmon XML events from Windows Event Log or stdin pipe.
// Normalizes Event IDs 1,3,11,23 to the same ProcessFileEvent JSON schema.
//
// Sysmon Event ID mapping:
//   1  -> Process Create     -> EventType: "execve"
//   3  -> Network Connection -> EventType: "network_connect"
//   11 -> File Created       -> EventType: "file_create"
//   23 -> File Delete        -> EventType: "file_delete"
//   26 -> File Delete Logged -> EventType: "file_delete"

//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// SysmonEvent is the top-level XML envelope from Windows Event Log
type SysmonEvent struct {
	XMLName xml.Name     `xml:"Event"`
	System  SysmonSystem `xml:"System"`
	Data    []SysmonData `xml:"EventData>Data"`
}

type SysmonSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
		GUID string `xml:"Guid,attr"`
	} `xml:"Provider"`
	EventID     int    `xml:"EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	Execution struct {
		ProcessID uint32 `xml:"ProcessID,attr"`
		ThreadID  uint32 `xml:"ThreadID,attr"`
	} `xml:"Execution"`
	Computer string `xml:"Computer"`
}

type SysmonData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// ProcessFileEvent — identical schema to Linux eBPF output
type ProcessFileEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	PID       uint32 `json:"pid"`
	PPID      uint32 `json:"ppid"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Process   string `json:"process"`
	FilePath  string `json:"file_path"`
	Args      string `json:"args"`
	Source    string `json:"source"`
	Hashes    string `json:"hashes,omitempty"`
	DestIP    string `json:"dest_ip,omitempty"`
	DestPort  string `json:"dest_port,omitempty"`
	User      string `json:"user,omitempty"`
}

var sysmonEventTypeMap = map[int]string{
	1:  "execve",
	3:  "network_connect",
	11: "file_create",
	23: "file_delete",
	26: "file_delete",
}

type SysmonParser struct {
	output *json.Encoder
}

func NewSysmonParser(w io.Writer) *SysmonParser {
	return &SysmonParser{output: json.NewEncoder(w)}
}

func dataMap(fields []SysmonData) map[string]string {
	m := make(map[string]string, len(fields))
	for _, f := range fields {
		m[f.Name] = strings.TrimSpace(f.Value)
	}
	return m
}

func parsePID(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 32)
	return uint32(v)
}

func parseTimestamp(s string) string {
	t, err := time.Parse("2006-01-02T15:04:05.999999999Z", s)
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (p *SysmonParser) Parse(rawXML string) (*ProcessFileEvent, error) {
	var ev SysmonEvent
	if err := xml.Unmarshal([]byte(rawXML), &ev); err != nil {
		return nil, fmt.Errorf("xml unmarshal: %w", err)
	}

	eventType, ok := sysmonEventTypeMap[ev.System.EventID]
	if !ok {
		return nil, nil
	}

	d := dataMap(ev.Data)
	ts := parseTimestamp(ev.System.TimeCreated.SystemTime)

	out := &ProcessFileEvent{
		Timestamp: ts,
		EventType: eventType,
		PID:       parsePID(d["ProcessId"]),
		PPID:      parsePID(d["ParentProcessId"]),
		Source:    "sysmon",
		User:      d["User"],
	}

	switch ev.System.EventID {
	case 1:
		out.Process  = d["Image"]
		out.FilePath = d["Image"]
		out.Args     = d["CommandLine"]
		out.Hashes   = d["Hashes"]
	case 3:
		out.Process  = d["Image"]
		out.DestIP   = d["DestinationIp"]
		out.DestPort = d["DestinationPort"]
		out.Args     = fmt.Sprintf("%s -> %s:%s", d["SourceIp"], d["DestinationIp"], d["DestinationPort"])
	case 11:
		out.Process  = d["Image"]
		out.FilePath = d["TargetFilename"]
		out.Hashes   = d["Hashes"]
	case 23, 26:
		out.Process  = d["Image"]
		out.FilePath = d["TargetFilename"]
		out.Hashes   = d["Hashes"]
	}

	if out.FilePath == "" && out.EventType != "network_connect" {
		return nil, nil
	}

	return out, nil
}

func (p *SysmonParser) Emit(ev *ProcessFileEvent) error {
	return p.output.Encode(ev)
}

func (p *SysmonParser) ProcessStream(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		ev, err := p.Parse(line)
		if err != nil || ev == nil {
			continue
		}
		_ = p.Emit(ev)
	}
}

func main() {
	parser := NewSysmonParser(os.Stdout)
	parser.ProcessStream(os.Stdin)
}
