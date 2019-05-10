package nessus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
)

//Scans on the Nessus server
type Scans struct {
	Folders   []FolderResource `json:"folders"`
	Scans     []ScanResource   `json:"scans"`
	Timestamp int              `json:"timestamp"`
}

//ScanResource of scans
type ScanResource struct {
	FolderID             int         `json:"folder_id"`
	Type                 string      `json:"type"`
	Read                 bool        `json:"read"`
	LastModificationDate int         `json:"last_modification_date"`
	CreationDate         int         `json:"creation_date"`
	Status               string      `json:"status"`
	UUID                 string      `json:"uuid"`
	Shared               bool        `json:"shared"`
	UserPermissions      int         `json:"user_permissions"`
	Owner                string      `json:"owner"`
	Timezone             interface{} `json:"timezone"`
	Rrules               interface{} `json:"rrules"`
	Starttime            interface{} `json:"starttime"`
	Enabled              bool        `json:"enabled"`
	Control              bool        `json:"control"`
	Name                 string      `json:"name"`
	ID                   int         `json:"id"`
}

//Scan information
type Scan struct {
	UUID     string       `json:"uuid"`
	Settings ScanSettings `json:"settings"`
}

//ScanSettings results
type ScanSettings struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Emails       string `json:"emails"`
	Enabled      bool   `json:"enabled"`
	Launch       string `json:"launch"`
	FolderID     int    `json:"folder_id"`
	PolicyID     int    `json:"policy_id"`
	ScannerID    int    `json:"scasnner_id"`
	TextTargets  string `json:"text_targets"`
	UseDashboard bool   `json:"use_dashboard"`
}

//ListScans available
func (n *Nessus) ListScans() (*Scans, error) {
	resp, err := n.get("scans")
	if err != nil {
		return nil, err
	}
	s := &Scans{}
	json.NewDecoder(resp).Decode(s)
	return s, nil
}

//ExportScan file number
func (n *Nessus) ExportScan(scanID int, format string) (int, error) {
	uri := fmt.Sprintf("scans/%d/export", scanID)
	values := url.Values{}
	values.Set("format", format)
	resp, err := n.post(uri, values)
	if err != nil {
		return 0, err
	}
	type file struct {
		File int `json:"file"`
	}
	f := &file{}
	json.NewDecoder(resp).Decode(f)
	return f.File, nil
}

//DownloadScan data
func (n *Nessus) DownloadScan(scanID, fileID int) ([]byte, error) {
	uri := fmt.Sprintf("scans/%d/export/%d/download", scanID, fileID)
	resp, err := n.get(uri)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	_, err = b.ReadFrom(resp)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

//ExportStatus of scan
func (n *Nessus) ExportStatus(scanID, fileID int) (string, error) {
	uri := fmt.Sprintf("scans/%d/export/%d/status", scanID, fileID)
	resp, err := n.get(uri)
	if err != nil {
		return "", err
	}
	type stat struct {
		Status string `json:"status"`
	}
	s := &stat{}
	json.NewDecoder(resp).Decode(s)
	return s.Status, nil
}

//ScanResponse once can is created
type ScanResponse struct {
	Scan struct {
		CreationDate           int    `json:"creation_date"`
		CustomTargets          string `json:"custom_targets"`
		DefaultPermissions     int    `json:"default_permissions"`
		Description            string `json:"description"`
		Emails                 string `json:"emails"`
		ID                     int    `json:"id"`
		LastModificationDate   int    `json:"last_modification_date"`
		Name                   string `json:"name"`
		NotificationFilterType string `json:"notification_filter_type"`
		NotificationFilters    string `json:"notificaiton_filters"`
		Owner                  string `json:"owner"`
		OwnerID                int    `json:"owner_id"`
		PolicyID               int    `json:"policy_id"`
		Enabled                bool   `json:"enabled"`
		Rrules                 string `json:"rrules"`
		ScannerID              int    `json:"scanner_id"`
		Shared                 int    `json:"shared"`
		StartTime              string `json:"starttime"`
		TagID                  int    `json:"tag_id"`
		TimeZone               string `json:"timezone"`
		Type                   string `json:"type"`
		UserPermissions        int    `json:"user_permissions"`
		UUID                   string `json:"uuid"`
		UseDashboard           bool   `json:"use_dashboard"`
	} `json:"scan"`
}

//CreateScan for Nessus
func (n *Nessus) CreateScan(scanData *Scan) (*ScanResponse, error) {
	values, _ := json.Marshal(scanData)
	resp, err := n.sendJSON("scans", values, "POST")
	if err != nil {
		return nil, err
	}
	s := &ScanResponse{}
	err = json.NewDecoder(resp.Body).Decode(s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

//LaunchScan for Nessus
func (n *Nessus) LaunchScan(scanID int) (string, error) {
	uri := fmt.Sprintf("scans/%d/launch", scanID)
	resp, err := n.post(uri, nil)
	if err != nil {
		return "", err
	}
	type response struct {
		ScanUUID string `json:"scan_uuid"`
	}
	r := &response{}
	err = json.NewDecoder(resp).Decode(r)
	if err != nil {
		return "", err
	}
	return r.ScanUUID, nil
}

//ScanStatus for Nessus
func (n *Nessus) ScanStatus(scanID int) (string, error) {
	uri := fmt.Sprintf("scans/%d", scanID)
	resp, err := n.get(uri)
	if err != nil {
		return "", err
	}
	rdata, err := ioutil.ReadAll(resp)
	if err != nil {
		return "", err
	}
	return string(rdata), nil
}
