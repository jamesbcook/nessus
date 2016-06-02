package nessus

import "encoding/json"

type policyResource struct {
	Policies []Policy `json:"policies"`
}

//Policy of Scans
type Policy struct {
	TemplateUUID         interface{} `json:"template_uuid"`
	Description          interface{} `json:"description"`
	NoTarget             interface{} `json:"no_target"`
	Name                 string      `json:"name"`
	Owner                string      `json:"owner"`
	Visibility           string      `json:"visibility"`
	OwnerID              int         `json:"owner_id"`
	ID                   int         `json:"id"`
	Shared               int         `json:"shared"`
	UserPermissions      int         `json:"user_permissions"`
	CreationDate         int         `json:"creation_date"`
	LastModificationDate int         `json:"last_modification_date"`
}

//ListPolicy available
func (n *Nessus) ListPolicy() ([]Policy, error) {
	resp, err := n.get("policies")
	if err != nil {
		return nil, err
	}
	p := &policyResource{}
	err = json.NewDecoder(resp).Decode(p)
	if err != nil {
		return nil, err
	}
	return p.Policies, nil
}
