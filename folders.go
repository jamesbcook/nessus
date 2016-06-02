package nessus

import "encoding/json"

//Folders on Nessus
type folders struct {
	Folders []FolderResource `json:"folders"`
}

//FolderResource of files
type FolderResource struct {
	UnreadCount int    `json:"unread_count"`
	Custom      int    `json:"custom"`
	DefaultTag  int    `json:"default_tag"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	ID          int    `json:"id"`
}

//ListFolders on Nessus
func (n *Nessus) ListFolders() ([]FolderResource, error) {
	resp, err := n.get("folders")
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	f := &folders{}
	json.NewDecoder(resp).Decode(f)
	return f.Folders, nil
}
