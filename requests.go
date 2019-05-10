package nessus

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func (n *Nessus) get(path string) (io.ReadCloser, error) {
	uri := fmt.Sprintf("%s/%s", n.Server, path)
	client := &http.Client{}
	if n.Insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}
	req, _ := http.NewRequest("GET", uri, nil)
	cookie := fmt.Sprintf("token=%s;", n.Token)
	req.Header.Set("X-Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (n *Nessus) post(path string, values url.Values) (io.ReadCloser, error) {
	uri := fmt.Sprintf("%s/%s", n.Server, path)
	client := &http.Client{}
	if n.Insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}
	req, err := http.NewRequest("POST", uri, bytes.NewBufferString(values.Encode()))
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cookie := fmt.Sprintf("token=%s;", n.Token)
	req.Header.Set("X-Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil

}

func (n *Nessus) sendJSON(path string, values []byte, method string) (*http.Response, error) {
	uri := fmt.Sprintf("%s/%s", n.Server, path)
	client := &http.Client{}
	if n.Insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}
	req, err := http.NewRequest(strings.ToUpper(method), uri, bytes.NewBuffer(values))
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("Content-Type", "application/json")
	cookie := fmt.Sprintf("token=%s;", n.Token)
	req.Header.Set("X-Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil

}

/*
TODO: Empliment
func (n *Nessus) put(path string, values url.Values) (io.ReadCloser, error) {
}
*/
func (n *Nessus) delete(path string) (*http.Response, error) {
	uri := fmt.Sprintf("%s/%s", n.Server, path)
	client := &http.Client{}
	if n.Insecure {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}
	req, err := http.NewRequest("DELETE", uri, nil)
	if err != nil {
		log.Println(err)
	}
	cookie := fmt.Sprintf("token=%s;", n.Token)
	req.Header.Set("X-Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
