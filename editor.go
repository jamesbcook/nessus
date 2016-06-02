package nessus

import (
	"encoding/json"
	"fmt"
)

type template struct {
	Templates []Template `json:"templates"`
}

//Template for Policy and Scans
type Template struct {
	UUID             string `json:"uuid"`
	Name             string `json:"name"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	CloudOnly        bool   `json:"cloud_only"`
	SubscriptionOnly bool   `json:"subscription_only"`
	IsAgent          bool   `json:"is_agent"`
	MoreInfo         string `json:"more_info"`
}

//ListEditorPolicy available
func (n *Nessus) ListEditorPolicy() ([]Template, error) {
	resp, err := n.get("editor/policy/templates")
	if err != nil {
		return nil, err
	}
	t := &template{}
	err = json.NewDecoder(resp).Decode(t)
	if err != nil {
		fmt.Println(err)
	}
	return t.Templates, nil
}

//ListEditorScan available
func (n *Nessus) ListEditorScan() ([]Template, error) {
	resp, err := n.get("editor/scan/templates")
	if err != nil {
		return nil, err
	}
	t := &template{}
	err = json.NewDecoder(resp).Decode(t)
	if err != nil {
		fmt.Println(err)
	}
	return t.Templates, nil
}
