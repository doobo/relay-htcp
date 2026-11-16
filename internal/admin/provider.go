package admin

import "time"

// Provider is implemented by the tunnel Server and the tunnel Pool. It gives
// the admin backend role-specific live status and config handling. The admin
// package stays generic; all role-specific validation and hot-apply logic
// lives with the tunnel code.
type Provider interface {
	// Role returns "server" or "client".
	Role() string
	// Status returns the live role-specific status. Version/UptimeSec/
	// StartedAt are filled in by the admin server.
	Status() Status
	// ValidateConfigYAML parses and validates YAML without applying it.
	ValidateConfigYAML(y string) error
	// ApplyConfigYAML hot-applies already-validated YAML to the running
	// instance and reports what took effect and what needs a restart.
	ApplyConfigYAML(y string) (SaveReport, error)
	// CurrentConfigYAML returns the effective in-memory configuration as
	// canonical YAML.
	CurrentConfigYAML() string
	// ConfigFormSchema describes the structured editor for this role. The
	// admin package uses it to build the form from CurrentConfigYAML and to
	// merge form edits back into YAML, so new tunables only need to be added
	// here.
	ConfigFormSchema() FormSchema
}

// FormSchema is the ordered layout of the structured config editor.
type FormSchema struct {
	Sections []FormSection `json:"sections"`
}

// FormSection groups related fields.
type FormSection struct {
	Title  string      `json:"title"`
	Fields []FormField `json:"fields"`
}

// FormFieldType selects the widget and the value conversion used when the
// form is submitted.
type FormFieldType string

const (
	FormText     FormFieldType = "text"
	FormSecret   FormFieldType = "secret"   // never returned to the browser
	FormNumber   FormFieldType = "number"   // int
	FormBool     FormFieldType = "bool"     // checkbox
	FormDuration FormFieldType = "duration" // Go duration string, e.g. "15s"
	FormSelect   FormFieldType = "select"
	FormCSV      FormFieldType = "csv"   // comma-separated string list
	FormTable    FormFieldType = "table" // repeated rows, described by Columns
)

// FormField is one editable value or one table column.
type FormField struct {
	// Path is a dot-separated YAML path ("tunnel.heartbeat") or, inside a
	// table's Columns, a plain row key ("target").
	Path        string        `json:"path"`
	Label       string        `json:"label"`
	Type        FormFieldType `json:"type"`
	Help        string        `json:"help,omitempty"`
	Placeholder string        `json:"placeholder,omitempty"`
	Options     []string      `json:"options,omitempty"`
	Columns     []FormField   `json:"columns,omitempty"`
}

// ConfigForm is the API payload of GET /api/config/form: the schema, the
// current values (secrets masked to "") and metadata for the UI.
type ConfigForm struct {
	Role     string         `json:"role"`
	Source   string         `json:"source"`
	Sections []FormSection  `json:"sections"`
	Values   map[string]any `json:"values"`
}

// SaveReport describes what a config save changed.
type SaveReport struct {
	Applied         []string `json:"applied"`
	RestartRequired []string `json:"restart_required"`
}

// Status is the live admin status. Exactly one of Server/Client is set.
type Status struct {
	Role      string        `json:"role"`
	Version   string        `json:"version"`
	UptimeSec int64         `json:"uptime_sec"`
	StartedAt int64         `json:"started_at"`
	Server    *ServerStatus `json:"server,omitempty"`
	Client    *ClientStatus `json:"client,omitempty"`
}

// ServerStatus is the live state of a tunnel server.
type ServerStatus struct {
	ListenAddr    string       `json:"listen_addr"`
	TLS           bool         `json:"tls"`
	ActiveTunnels int          `json:"active_tunnels"`
	ActiveStreams []StreamStat `json:"active_streams"`
	BytesIn       uint64       `json:"bytes_in"`
	BytesOut      uint64       `json:"bytes_out"`
	DecoyViews    uint64       `json:"decoy_views"`
}

// StreamStat is one live data stream on the server.
type StreamStat struct {
	ID        int64  `json:"id"`
	Route     string `json:"route"`
	Token     string `json:"token"`
	Remote    string `json:"remote"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
	StartedAt int64  `json:"started_at"`
}

// ClientStatus is the live state of a tunnel client.
type ClientStatus struct {
	ServerAddr  string         `json:"server_addr"`
	Slots       []SlotStat     `json:"slots"`
	Listeners   []ListenerStat `json:"listeners"`
	ActiveConns []ConnStat     `json:"active_conns"`
}

// SlotState is a pool slot lifecycle state.
type SlotState string

const (
	SlotStateDialing      SlotState = "dialing"
	SlotStateConnected    SlotState = "connected"
	SlotStateReconnecting SlotState = "reconnecting"
)

// SlotStat is one tunnel pool connection.
type SlotStat struct {
	Index       int       `json:"index"`
	State       SlotState `json:"state"`
	ConnectedAt int64     `json:"connected_at,omitempty"`
	LastPongAt  int64     `json:"last_pong_at,omitempty"`
}

// ListenerStat is one local listener.
type ListenerStat struct {
	Local       string `json:"local"`
	Target      string `json:"target"`
	ActiveConns int    `json:"active_conns"`
}

// ConnStat is one active local connection through the tunnel.
type ConnStat struct {
	Local     string `json:"local"`
	From      string `json:"from"`
	Route     string `json:"route"`
	StartedAt int64  `json:"started_at"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
}

// DefaultSessionTTL is the session lifetime when unset.
const DefaultSessionTTL = 24 * time.Hour
