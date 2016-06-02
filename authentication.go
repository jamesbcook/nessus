package nessus

import (
	"encoding/json"
	"errors"
	"net/url"
)

type token struct {
	Token string
}

//Nessus holds server and authenticaiton information
type Nessus struct {
	Token    string
	Server   string
	Insecure bool
}

//Login to Nessus server
func Login(user, password, server string, insecure bool) (*Nessus, error) {
	n := &Nessus{Server: server, Insecure: insecure}
	values := url.Values{}
	values.Set("username", user)
	values.Set("password", password)
	resp, err := n.post("session", values)
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	t := &token{}
	json.NewDecoder(resp).Decode(t)
	n.Token = t.Token
	return n, nil
}

//Logout of Nessus
func (n *Nessus) Logout() error {
	resp, err := n.delete("session")
	if err != nil {
		return err
	}
	if resp.StatusCode == 200 {
		return nil
	} else if resp.StatusCode == 401 {
		return errors.New("No Session Exists")
	} else {
		return errors.New("Status Code not found")
	}
}
