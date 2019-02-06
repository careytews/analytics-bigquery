package main

//
// Bigquery loader for the analytics cluster.  Takes events on input queue
// and restructures for loading into a bigquery table called 'cyberprobe'.
// One row per event.
//
// No output queues are used.
//

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	dt "github.com/trustnetworks/analytics-common/datatypes"
	"github.com/trustnetworks/analytics-common/utils"
	"github.com/trustnetworks/analytics-common/worker"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/bigquery/v2"
)

// Program name, for the log.
const pgm string = "bigquery"

// Batch size for insert
var insert_batch = 100

// Worker handle.
type work struct {
	client  *http.Client      // HTTP client
	key     string            // Private key file
	project string            // Project name
	dataset string            // Dataset name
	table   string            // Table name
	svc     *bigquery.Service // Bigquery service handle.

	count int
	rows  bigquery.TableDataInsertAllRequest
}

// The set of HTTP headers which are stored in the BigQuery table.
// Don't forget to update schema below when changing.
var wantedHttpHeaders map[string]bool = map[string]bool{
	"Accept":                      true,
	"Accept-Charset":              true,
	"Accept-Language":             true,
	"Access-Control-Allow-Origin": true,
	"Authorization":               true,
	"Connection":                  true,
	"Content-Encoding":            true,
	"Content-Language":            true,
	"Content-Location":            true,
	"Content-Type":                true,
	"Cookie":                      true,
	"Date":                        true,
	"ETag":                        true,
	"Forwarded":                   true,
	"Host":                        true,
	"Link":                        true,
	"Location":                    true,
	"Origin":                      true,
	"Proxy-Authorization":         true,
	"Referer":                     true,
	"Server":                      true,
	"Set-Cookie":                  true,
	"Upgrade":                     true,
	"User-Agent":                  true,
	"Via":                         true,
	"WWW-Authenticate":            true,
	"X-Forwarded-For":             true,
	"X-Forwarded-Host":            true,
}

// Initialisaition
func (s *work) init() error {

	// Get environment variables.
	s.key = utils.Getenv("KEY", "private.json")
	s.project = utils.Getenv("BIGQUERY_PROJECT", "")
	s.dataset = utils.Getenv("BIGQUERY_DATASET", "cyberprobe")
	s.table = utils.Getenv("RAW_TABLE", "cyberprobe")

	// Read the key file
	key, err := ioutil.ReadFile(s.key)
	if err != nil {
		utils.Log("Couldn't read key file: %s", err.Error())
		return err
	}

	// Create JWT from key file
	config, err := google.JWTConfigFromJSON(key)
	if err != nil {
		utils.Log("JWTConfigFromJSON: %s", err.Error())
		return err
	}

	// Access scope
	config.Scopes = []string{bigquery.BigqueryScope}

	// Create service client.
	s.client = config.Client(oauth2.NoContext)

	// Connect to BigQuery
	s.svc, err = bigquery.New(s.client)
	if err != nil {
		utils.Log("Coulnd't create client: %s", err.Error())
		return err
	}

	utils.Log("Connected.")

	// See if the table already exists.
	_, err = s.svc.Tables.Get(s.project, s.dataset, s.table).Do()
	if err != nil {

		// Table does not exist, it will be created.
		utils.Log("Table %s does not exist, creating...", s.table)

		// Create table definition.
		var tbl bigquery.Table
		tbl.TableReference = &bigquery.TableReference{
			ProjectId: s.project,
			DatasetId: s.dataset,
			TableId:   s.table,
		}
		tbl.TimePartitioning = &bigquery.TimePartitioning{Type: "DAY"}
		tbl.Kind = "bigquery#table"
		tbl.Description = "cyberprobe event table"
		tbl.Schema = &bigquery.TableSchema{}
		tbl.Schema.Fields = []*bigquery.TableFieldSchema{
			&bigquery.TableFieldSchema{
				Name: "id",
				Mode: "REQUIRED",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "time",
				Mode: "REQUIRED",
				Type: "TIMESTAMP",
			},
			&bigquery.TableFieldSchema{
				Name: "action",
				Mode: "REQUIRED",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "device",
				Mode: "REQUIRED",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "udp_src",
				Mode: "NULLABLE",
				Type: "INTEGER",
			},
			&bigquery.TableFieldSchema{
				Name: "udp_dest",
				Mode: "NULLABLE",
				Type: "INTEGER",
			},
			&bigquery.TableFieldSchema{
				Name: "tcp_src",
				Mode: "NULLABLE",
				Type: "INTEGER",
			},
			&bigquery.TableFieldSchema{
				Name: "tcp_dest",
				Mode: "NULLABLE",
				Type: "INTEGER",
			},
			&bigquery.TableFieldSchema{
				Name: "ipv4_src",
				Mode: "NULLABLE",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "ipv4_dest",
				Mode: "NULLABLE",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "type",
				Mode: "NULLABLE",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "query",
				Mode: "REPEATED",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "answer",
				Mode: "REPEATED",
				Type: "RECORD",
				Fields: []*bigquery.TableFieldSchema{
					&bigquery.TableFieldSchema{
						Name: "name",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "address",
						Mode: "NULLABLE",
						Type: "STRING",
					},
				},
			},
			&bigquery.TableFieldSchema{
				Name: "method",
				Mode: "NULLABLE",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "status",
				Mode: "NULLABLE",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "code",
				Mode: "NULLABLE",
				Type: "INTEGER",
			},
			&bigquery.TableFieldSchema{
				Name: "size",
				Mode: "NULLABLE",
				Type: "INTEGER",
			},
			&bigquery.TableFieldSchema{
				Name: "header",
				Mode: "NULLABLE",
				Type: "RECORD",
				Fields: []*bigquery.TableFieldSchema{
					&bigquery.TableFieldSchema{
						Name: "accept",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "acceptcharset",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "acceptlanguage",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "accesscontrolalloworigin",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "authorization",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "connection",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "contentencoding",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "contentlanguage",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "contentlocation",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "contenttype",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "cookie",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "date",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "etag",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "forwarded",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "host",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "link",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "location",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "origin",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "proxyauthorization",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "referer",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "server",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "setcookie",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "upgrade",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "useragent",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "via",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "wwwauthenticate",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "xforwardedfor",
						Mode: "NULLABLE",
						Type: "STRING",
					},
					&bigquery.TableFieldSchema{
						Name: "xforwardedhost",
						Mode: "NULLABLE",
						Type: "STRING",
					},
				},
			},
			&bigquery.TableFieldSchema{
				Name: "url",
				Mode: "NULLABLE",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "from",
				Mode: "NULLABLE",
				Type: "STRING",
			},
			&bigquery.TableFieldSchema{
				Name: "to",
				Mode: "REPEATED",
				Type: "STRING",
			},
		}

		// Create table.
		_, err = s.svc.Tables.Insert(s.project, s.dataset,
			&tbl).Do()
		if err != nil {
			utils.Log("Table create error: %s", err.Error())
			return err
		}

		utils.Log("Table %s created.", s.table)

	} else {
		utils.Log("Table %s exists.", s.table)
	}

	return nil

}

// Handler, invoked for each event.
func (s *work) Handle(msg []uint8, w *worker.Worker) error {

	//	utils.Log("%s", msg)

	// Decode JSON event
	var e dt.Event
	err := json.Unmarshal(msg, &e)
	if err != nil {
		utils.Log("Couldn't unmarshal json: %s", err.Error())
		return nil
	}

	row := &bigquery.TableDataInsertAllRequestRows{
		Json: map[string]bigquery.JsonValue{},
	}

	s.rows.Rows = append(s.rows.Rows, row)

	// Populate data in insert request
	values := &row.Json
	if e.Id != "" {
		(*values)["id"] = e.Id
	}
	if e.Action != "" {
		(*values)["action"] = e.Action
	}
	if e.Device != "" {
		(*values)["device"] = e.Device
	}
	if e.Time != "" {
		(*values)["time"] = e.Time
	}

	// Convert HTTP header list into fields.
	h := map[string]string{}

	if e.HttpRequest != nil && len(e.HttpRequest.Header) > 0 {
		for k, v := range e.HttpRequest.Header {
			if _, ok := wantedHttpHeaders[k]; ok {
				k = strings.Replace(k, "-", "", -1)
				k = strings.ToLower(k)
				h[k] = v
			}
		}
	}

	if e.HttpResponse != nil && len(e.HttpResponse.Header) > 0 {
		for k, v := range e.HttpResponse.Header {
			if _, ok := wantedHttpHeaders[k]; ok {
				k = strings.Replace(k, "-", "", -1)
				k = strings.ToLower(k)
				h[k] = v
			}
		}
	}

	switch e.Action {
	case "http_request":
		if e.HttpRequest != nil {
			(*values)["method"] = e.HttpRequest.Method
		}
		(*values)["header"] = &h
	case "http_response":
		if e.HttpResponse != nil {
			(*values)["status"] = e.HttpResponse.Status
			(*values)["code"] = e.HttpResponse.Code
		}
		(*values)["header"] = &h
	case "ftp_command":
		if e.FtpCommand != nil {
			(*values)["command"] = e.FtpCommand.Command
		}
	case "ftp_response":
		if e.FtpResponse != nil {
			(*values)["status"] = e.FtpResponse.Status
			(*values)["text"] = e.FtpResponse.Text
		}
	case "icmp":

	case "dns_message":
		if e.DnsMessage != nil {
			if e.DnsMessage.Query != nil {
				if len(e.DnsMessage.Query) > 0 {
					(*values)["query"] = e.DnsMessage.Query
				}
			}
			if e.DnsMessage.Answer != nil {
				if len(e.DnsMessage.Answer) > 0 {
					(*values)["answer"] = e.DnsMessage.Answer
				}
			}
			(*values)["type"] = e.DnsMessage.Type
		}
	case "sip_request":
		if e.SipRequest != nil {
			(*values)["method"] = e.SipRequest.Method
			(*values)["from"] = e.SipRequest.From
			(*values)["to"] = []string{e.SipRequest.To}
		}
	case "sip_response":
		if e.SipResponse != nil {
			(*values)["code"] = e.SipResponse.Code
			(*values)["status"] = e.SipResponse.Status
			(*values)["from"] = e.SipResponse.From
			(*values)["to"] = []string{e.SipResponse.To}
		}
	case "smtp_command":
		if e.SmtpCommand != nil {
			(*values)["command"] = e.SmtpCommand.Command
		}
	case "smtp_response":
		if e.SmtpResponse != nil {
			(*values)["status"] = e.SmtpResponse.Status
			(*values)["text"] = e.SmtpResponse.Text
		}
	case "smtp_data":
		if e.SmtpData != nil {
			(*values)["from"] = e.SmtpData.From
			(*values)["to"] = e.SmtpData.To
		}
	case "ntp_timestamp":
	case "ntp_control":
	case "ntp_private":
	}

	if e.Url != "" {
		(*values)["url"] = e.Url
	}

	// Convert source address list into table fields.
	for _, v := range e.Src {

		var cls, addr string

		val_parts := strings.SplitN(v, ":", 2)
		cls = val_parts[0]
		if len(val_parts) > 1 {
			addr = val_parts[1]
		} else {
			addr = ""
		}

		switch {
		case cls == "ipv4":
			(*values)["ipv4_src"] = addr
		case cls == "tcp":
			(*values)["tcp_src"] = addr
		case cls == "udp":
			(*values)["udp_src"] = addr
		}

	}

	// Convert source address list into table fields.
	for _, v := range e.Dest {

		var cls, addr string

		val_parts := strings.SplitN(v, ":", 2)
		cls = val_parts[0]
		if len(val_parts) > 1 {
			addr = val_parts[1]
		} else {
			addr = ""
		}

		switch {
		case cls == "ipv4":
			(*values)["ipv4_dest"] = addr
		case cls == "tcp":
			(*values)["tcp_dest"] = addr
		case cls == "udp":
			(*values)["udp_dest"] = addr
		}

	}

	s.count++

	if s.count > insert_batch {

		// FIXME: Don't need to do this at all?
		s.rows.Kind = "biquery#tableDataInsertAllRequest"

		// Table insert.
		_, err = s.svc.Tabledata.InsertAll(s.project, s.dataset,
			s.table, &s.rows).Do()
		if err != nil {
			utils.Log("InsertAll: %s", err.Error())
			return nil
		}

		s.count = 0
		s.rows.Rows = []*bigquery.TableDataInsertAllRequestRows{}

	}

	return nil

}

func main() {

	var w worker.QueueWorker
	var s work
	utils.LogPgm = pgm

	utils.Log("Initialising...")

	// Initialise BigQuery.
	err := s.init()
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	// Initialise.
	var input string
	var output []string

	if len(os.Args) > 0 {
		input = os.Args[1]
	}
	if len(os.Args) > 2 {
		output = os.Args[2:]
	}

	err = w.Initialise(input, output, pgm)
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	utils.Log("Initialisation complete.")

	// Invoke Wye event handling.
	w.Run(&s)

}
