# Nessus

## Interact with Nessus REST

### Example Usage

```go
package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "strings"
    "time"
    "github.com/jamesbcook/nessus"
)

func main() {
    user := flag.String("user", "", "Nessus Username")
    pass := flag.String("pass", "", "Nessus Password")
    host := flag.String("host", "", "Nessus Host (https://localhost:8834)")
    insecure := flag.Bool("insecure", true, "Checks for valid Nessus certificate")
    flag.Parse()
    nessus, err := nessus.Login(*user, *pass, *host, *insecure)
    if err != nil {
        log.Fatal(err)
    }
    scans, err := nessus.ListScans()
    if err != nil {
         log.Fatal(err)
    }
    for _, scan := range scans.Scans {
        fileID, err := nessus.ExportScan(scan.ID, "csv")
        if err != nil {
            log.Fatal(err)
        }
        for {
            status, err := nessus.ExportStatus(scan.ID, fileID)
            if err != nil {
                log.Fatal(err)
            }
            if status == "ready" {
                break
            } else {
                fmt.Println("Current export status:", status)
            }
        }
        scanData, err := nessus.DownloadScan(scan.ID, fileID)
        if err != nil {
            log.Fatal(err)
        }
        fileName := fmt.Sprintf("%s_%d.csv", strings.Replace(scan.Name, " ", "_", -1), time.Now().Unix())
        fileLength := len(scanData)
        fmt.Printf("Writing to %d bytes to %s\n", fileLength, fileName)
        ioutil.WriteFile(fileName, scanData, 0755)
    }
}

```

### Package provides

* Authentication
  * Login
  * Logout
* Folders
  * ListFolders
* Policy
  * ListPolicy
  * LimitPorts
* Scans
  * ListScans
  * ExportScan
  * DownloadScan
  * ExportStatus
  * CreateScan
  * LaunchScan
  * ScanStatus