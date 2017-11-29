package nessus

import (
	"encoding/json"
	"fmt"
)

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

/*
//EditSettings in Policy
type EditSettings struct {
	UUID     interface{} `json:"uuid"`
	Settings Settings    `json:"settings"`
}

//Settings in a Policy
type Settings struct {
	ACLS                          []ACLS `json:"acls"`
	AdditionalSnmpPort1           string `json:"additional_snmp_port1"`
	AdditionalSnmpPort2           string `json:"additional_snmp_port2"`
	AdditionalSnmpPort3           string `json:"additional_snmp_port3"`
	AdtranAosOfflineConfigs       string `json:"adtran_aos_offline_configs"`
	AllowPostScanEditing          string `json:"allow_post_scan_editing"`
	ApmForceUpdates               string `json:"apm_force_updates"`
	ApmUpdateTimeout              string `json:"apm_update_timeout"`
	ArpPing                       string `json:"arp_ping"`
	AvGracePeriod                 string `json:"av_grace_period"`
	AwsApNortheast1               string `json:"aws_ap_northeast_1"`
	AwsApSoutheast1               string `json:"aws_ap_southeast_1"`
	AwsApSoutheast2               string `json:"aws_ap_southeast_2"`
	AwsEuWest1                    string `json:"aws_eu_west_1"`
	AwsSaEast1                    string `json:"aws_sa_east_1"`
	AWSUIRegionType               string `json:"aws_ui_region_type"`
	AWSUIEast1                    string `json:"aws_us_east_1"`
	AwsUsGovWest1                 string `json:"aws_us_gov_west_1"`
	AwsUsWest1                    string `json:"aws_us_west_1"`
	AwsUsWest2                    string `json:"aws_us_west_2"`
	AwsUseHTTPS                   string `json:"aws_use_https"`
	AwsVerifySsl                  string `json:"aws_verify_ssl"`
	BrocadeOfflineConfigs         string `json:"brocade_offline_configs"`
	CheckCrl                      string `json:"check_crl"`
	CiscoConfigToAudit            string `json:"cisco_config_to_audit"`
	CiscoOfflineConfigs           string `json:"cisco_offline_configs"`
	DellF10OfflineConfigs         string `json:"dell_f10_offline_configs"`
	Description                   string `json:"description"`
	DetectSsl                     string `json:"detect_ssl"`
	DisplayUnreachableHosts       string `json:"display_unreachable_hosts"`
	DontUseNtlmv1                 string `json:"dont_use_ntlmv1"`
	EnableAdminShares             string `json:"enable_admin_shares"`
	EnumDomainUsersEndUID         string `json:"enum_domain_users_end_uid"`
	EnumDomainUsersStartUID       string `json:"enum_domain_users_start_uid"`
	EnumLocalUsersEndUID          string `json:"enum_local_users_end_uid"`
	EnumLocalUsersStartUID        string `json:"enum_local_users_start_uid"`
	EnumerateAllCiphers           string `json:"enumerate_all_ciphers"`
	ExtremeosOfflineConfigs       string `json:"extremeos_offline_configs"`
	FastNetworkDiscovery          string `json:"fast_network_discovery"`
	FireeyeOfflineConfigs         string `json:"fireeye_offline_configs"`
	HostWhitelist                 string `json:"host_whitelist"`
	HTTPLoginAuthRegexNocase      string `json:"http_login_auth_regex_nocase"`
	HTTPLoginAuthRegexOnHeaders   string `json:"http_login_auth_regex_on_headers"`
	HTTPLoginInvertAuthRegex      string `json:"http_login_invert_auth_regex"`
	HTTPLoginMaxRedir             string `json:"http_login_max_redir"`
	HTTPLoginMethod               string `json:"http_login_method"`
	HuaweiOfflineConfigs          string `json:"huawei_offline_configs"`
	IcmpPing                      string `json:"icmp_ping"`
	IcmpPingRetries               string `json:"icmp_ping_retries"`
	IcmpUnreachMeansHostDown      string `json:"icmp_unreach_means_host_down"`
	JunosOfflineConfigs           string `json:"junos_offline_configs"`
	LogLiveHosts                  string `json:"log_live_hosts"`
	LogWholeAttack                string `json:"log_whole_attack"`
	MaxChecksPerHost              string `json:"max_checks_per_host"`
	MaxHostsPerScan               string `json:"max_hosts_per_scan"`
	MaxSimultTCPSessionsPerHost   string `json:"max_simult_tcp_sessions_per_host"`
	MaxSimultTCPSessionsPerScan   string `json:"max_simult_tcp_sessions_per_scan"`
	ModbusEndReg                  string `json:"modbus_end_reg"`
	ModbusStartReg                string `json:"modbus_start_reg"`
	Name                          string `json:"name"`
	NetappOfflineConfigs          string `json:"netapp_offline_configs"`
	NetworkReceiveTimeout         string `json:"network_receive_timeout"`
	NetworkType                   string `json:"network_type"`
	NeverSendWinCRedsInTheClear   string `json:"never_send_win_creds_in_the_clear"`
	OnlyPortscanIfEnumFailed      string `json:"only_portscan_if_enum_failed"`
	PatchAuditOverRexec           string `json:"patch_audit_over_rexec"`
	PatchAuditOverRsh             string `json:"patch_audit_over_rsh"`
	PatchAuditOverTelnet          string `json:"patch_audit_over_telnet"`
	PingTheRemoteHost             string `json:"ping_the_remote_host"`
	PortscanRange                 string `json:"portscan_range"`
	ProcurveConfigToAudit         string `json:"procurve_config_to_audit"`
	ProcurveOfflineConfigs        string `json:"procurve_offline_configs"`
	ProvidedCredsOnly             string `json:"provided_creds_only"`
	ReduceConnectionsOnCongestion string `json:"reduce_connections_on_congestion"`
	ReportParanoia                string `json:"report_paranoia"`
	ReportSupersededPatches       string `json:"report_superseded_patches"`
	ReportVerbosity               string `json:"report_verbosity"`
	RequestWindowsDomainInfo      string `json:"request_windows_domain_info"`
	ReverseLookup                 string `json:"reverse_lookup"`
	SafeChecks                    string `json:"safe_checks"`
	ScanNetwareHosts              string `json:"scan_netware_hosts"`
	ScanNetworkPrinters           string `json:"scan_network_printers"`
	ScanWebapps                   string `json:"scan_webapps"`
	SilentDependencies            string `json:"silent_dependencies"`
	SliceNetworkAddresses         string `json:"slice_network_addresses"`
	SMTPDomain                    string `json:"smtp_domain"`
	SMTPFrom                      string `json:"smtp_from"`
	SMTPTo                        string `json:"smtp_to"`
	SNMPort                       string `json:"snmp_port"`
	SNMPScanner                   string `json:"snmp_scanner"`
	SonicosOfflineConfigs         string `json:"sonicos_offline_configs"`
	SSHClientBanner               string `json:"ssh_client_banner"`
	SSHKnownHosts                 string `json:"ssh_known_hosts"`
	SSHNetstatScanner             string `json:"ssh_netstat_scanner"`
	SSHPort                       string `json:"ssh_port"`
	SSLProbPorts                  string `json:"ssl_prob_ports"`
	StartCotpTsap                 string `json:"start_cotp_tsap"`
	StartRemoteRegistry           string `json:"start_remote_registry"`
	StopCotpTsap                  string `json:"stop_cotp_tsap"`
	StopScanOnDisconnect          string `json:"stop_scan_on_disconnect"`
	SvcDetectionOnAllPorts        string `json:"svc_detection_on_all_ports"`
	SynFirewallDetection          string `json:"syn_firewall_detection"`
	SynScanner                    string `json:"syn_scanner"`
	TCPPing                       string `json:"tcp_ping"`
	TCPPingDestPorts              string `json:"tcp_ping_dest_ports"`
	TestDefaultOracleAccounts     string `json:"test_default_oracle_accounts"`
	TestLocalNessusHost           string `json:"test_local_nessus_host"`
	ThoroughTests                 string `json:"thorough_tests"`
	UDPPing                       string `json:"udp_ping"`
	UDPScanner                    string `json:"udp_scanner"`
	UnscannedClosed               string `json:"unscanned_closed"`
	VerifyOpenPorts               string `json:"verify_open_ports"`
	WinKnownBadHashes             string `json:"win_known_bad_hashes"`
	WinKnownGoodHashes            string `json:"win_known_good_hashes"`
	WmiNetstatScanner             string `json:"wmi_netstat_scanner"`
	WolMacAddresses               string `json:"wol_mac_addresses"`
	WolWaitTime                   string `json:"wol_wait_time"`
}

//ACLS permissions
type ACLS struct {
	Owner       int    `json:"owner"`
	Type        string `json:"type"`
	Permissions int    `json:"permissions"`
	ID          int    `json:"id"`
	Name        string `json:"name"`
}
*/

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

/*
//ConfigurePolicy blah
func (n *Nessus) ConfigurePolicy(id int, policy *EditSettings) (int, error) {
	values, err := json.Marshal(policy)
	if err != nil {
		return 0, err
	}
	uri := fmt.Sprintf("policies/%d", id)
	resp, err := n.postJSON(uri, values)
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}
*/

//PolicyPorts settings
type PolicyPorts struct {
	UUID     string `json:"template_uuid"`
	Settings struct {
		PortsScanRange string `json:"portscan_range"`
	} `json:"settings"`
}

//LimitPorts for a policy
func (n *Nessus) LimitPorts(id int, policyPorts *PolicyPorts) (int, error) {
	values, err := json.Marshal(policyPorts)
	if err != nil {
		return 0, err
	}
	uri := fmt.Sprintf("policies/%d", id)
	resp, err := n.sendJSON(uri, values, "PUT")
	if err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}
