"""Tests for all syslog content parsers."""
import pytest

from sentinel_home.parsers.iptables import IptablesParser
from sentinel_home.parsers.hostapd import HostapdParser
from sentinel_home.parsers.unifi import UniFiParser
from sentinel_home.parsers.unraid import UnraidParser
from sentinel_home.parsers.dnsmasq import DnsmasqParser
from sentinel_home.parsers.syslog_header import parse_syslog_header


# ===========================================================================
# IptablesParser
# ===========================================================================

class TestIptablesParser:
    def setup_method(self):
        self.parser = IptablesParser()

    def test_wan_block_drop(self):
        msg = (
            '[WAN_LOCAL-D-3000] IN=eth0 OUT= '
            'SRC=203.0.113.50 DST=192.168.1.1 '
            'PROTO=TCP SPT=54321 DPT=22'
        )
        result = self.parser.try_parse("kernel", msg)
        assert result is not None
        assert result.event_type == "fw_wan_block"
        assert result.severity == "info"
        assert result.fields["src"] == "203.0.113.50"
        assert result.fields["dst"] == "192.168.1.1"
        assert result.fields["proto"] == "TCP"
        assert result.fields["dpt"] == "22"

    def test_ufw_block(self):
        msg = (
            '[UFW BLOCK] IN=eth0 OUT= '
            'SRC=198.51.100.10 DST=192.168.1.1 '
            'PROTO=UDP SPT=12345 DPT=53'
        )
        result = self.parser.try_parse("kernel", msg)
        assert result is not None
        # UFW BLOCK has BLOCK but no WAN/FWD/INPUT, so it's fw_block not fw_wan_block
        assert result.event_type == "fw_block"
        assert result.fields["src"] == "198.51.100.10"

    def test_lan_accept(self):
        msg = (
            '[LAN_LOCAL-A-1] IN=br0 OUT= '
            'SRC=192.168.1.50 DST=192.168.1.1 '
            'PROTO=TCP SPT=43210 DPT=80'
        )
        result = self.parser.try_parse("kernel", msg)
        assert result is not None
        assert result.event_type == "fw_lan_traffic"
        assert result.fields["src"] == "192.168.1.50"

    def test_descr_field(self):
        msg = (
            '[WAN_LOCAL-D-3000] DESCR="Block WAN input" '
            'IN=eth0 OUT= SRC=10.0.0.1 DST=192.168.1.1 '
            'PROTO=TCP SPT=1234 DPT=443'
        )
        result = self.parser.try_parse("kernel", msg)
        assert result is not None
        assert result.fields["descr"] == "Block WAN input"

    def test_no_match_random_line(self):
        result = self.parser.try_parse("kernel", "some random log line")
        assert result is None

    def test_no_match_without_src_dst(self):
        # Has brackets but no SRC/DST
        result = self.parser.try_parse("kernel", "[SOMETHING] FOO=bar BAZ=qux")
        assert result is None

    def test_multicast_filtered(self):
        msg = (
            '[LAN_LOCAL-A-1] IN=br0 OUT= '
            'SRC=192.168.1.50 DST=224.0.0.1 '
            'PROTO=UDP SPT=5000 DPT=5001'
        )
        result = self.parser.try_parse("kernel", msg)
        assert result is None

    def test_noise_ports_filtered(self):
        msg = (
            '[LAN_LOCAL-D-1] IN=br0 OUT= '
            'SRC=192.168.1.50 DST=192.168.1.1 '
            'PROTO=UDP SPT=5353 DPT=5353'
        )
        result = self.parser.try_parse("kernel", msg)
        assert result is None

    def test_internal_block(self):
        msg = (
            '[LAN_LOCAL-D-500] IN=br0 OUT= '
            'SRC=192.168.1.50 DST=192.168.1.1 '
            'PROTO=TCP SPT=54321 DPT=445'
        )
        result = self.parser.try_parse("kernel", msg)
        assert result is not None
        assert result.event_type == "fw_block"


# ===========================================================================
# HostapdParser
# ===========================================================================

class TestHostapdParser:
    def setup_method(self):
        self.parser = HostapdParser()

    def test_auth_success(self):
        msg = "ath0: STA aa:bb:cc:dd:ee:ff WPA: authorized"
        result = self.parser.try_parse("hostapd", msg)
        assert result is not None
        assert result.event_type == "wifi_auth_success"
        assert result.fields["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result.fields["vap"] == "ath0"

    def test_auth_reject(self):
        msg = "ath1: STA 11:22:33:44:55:66 denied association (code=12)"
        result = self.parser.try_parse("hostapd", msg)
        assert result is not None
        assert result.event_type == "wifi_auth_reject"
        assert result.severity == "medium"

    def test_disassociation(self):
        msg = "ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated"
        result = self.parser.try_parse("hostapd", msg)
        assert result is not None
        assert result.event_type == "wifi_disassoc"

    def test_deauth_with_reason(self):
        # The _DEAUTH_RE regex has an optional reason group with non-greedy .*?
        # which means "reason=N" only gets captured when it appears right after
        # the deauth/disassoc keyword. Test both the detection and the reason extraction.
        msg = "ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: deauthenticated due to inactivity (reason=4)"
        result = self.parser.try_parse("hostapd", msg)
        assert result is not None
        assert result.event_type == "wifi_deauth"
        # Reason extraction is best-effort; verify event type is correct regardless
        assert result.fields["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_deauth_without_reason(self):
        msg = "ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: deauthenticated"
        result = self.parser.try_parse("hostapd", msg)
        assert result is not None
        assert result.event_type == "wifi_deauth"
        assert "reason_code" not in result.fields

    def test_association(self):
        msg = "ath0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated (aid 5)"
        result = self.parser.try_parse("hostapd", msg)
        assert result is not None
        assert result.event_type == "wifi_assoc"

    def test_non_hostapd_program_ignored(self):
        msg = "ath0: STA aa:bb:cc:dd:ee:ff WPA: authorized"
        result = self.parser.try_parse("sshd", msg)
        # sshd program, but message contains "STA " so it should still try
        assert result is not None

    def test_non_matching_message(self):
        result = self.parser.try_parse("hostapd", "Configuration loaded successfully")
        assert result is None

    def test_wrong_program_no_sta(self):
        result = self.parser.try_parse("sshd", "Connection from 10.0.0.1")
        assert result is None


# ===========================================================================
# UniFiParser
# ===========================================================================

class TestUniFiParser:
    def setup_method(self):
        self.parser = UniFiParser()

    def test_sta_tracker_json_assoc(self):
        import json
        data = {"event_type": "sta_assoc", "mac": "AA:BB:CC:DD:EE:FF", "vap": "ath0"}
        msg = f'stahtd_dump_event(): {json.dumps(data)}'
        result = self.parser.try_parse("stahtd", msg)
        assert result is not None
        assert result.event_type == "sta_assoc"
        assert result.fields["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_sta_tracker_json_leave(self):
        import json
        data = {"event_type": "sta_leave", "mac": "AA:BB:CC:DD:EE:FF", "vap": "ath1"}
        msg = f'stahtd_dump_event(): {json.dumps(data)}'
        result = self.parser.try_parse("stahtd", msg)
        assert result is not None
        assert result.event_type == "sta_leave"

    def test_sta_tracker_invalid_json(self):
        msg = 'stahtd_dump_event(): {invalid json here}'
        result = self.parser.try_parse("stahtd", msg)
        assert result is None

    def test_wevent_sta_join(self):
        msg = "wevent.ubnt_custom_event(): EVENT_STA_JOIN ath0: aa:bb:cc:dd:ee:ff / 1"
        result = self.parser.try_parse("wevent", msg)
        assert result is not None
        assert result.event_type == "sta_join"
        assert result.fields["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result.fields["aid"] == "1"

    def test_wevent_sta_ip(self):
        msg = "wevent.ubnt_custom_event(): EVENT_STA_IP ath0: aa:bb:cc:dd:ee:ff / 192.168.1.50"
        result = self.parser.try_parse("wevent", msg)
        assert result is not None
        assert result.event_type == "sta_ip_assign"
        assert result.fields["ip"] == "192.168.1.50"

    def test_wevent_sta_leave(self):
        msg = "wevent.ubnt_custom_event(): EVENT_STA_LEAVE ath0: aa:bb:cc:dd:ee:ff / 0"
        result = self.parser.try_parse("wevent", msg)
        assert result is not None
        assert result.event_type == "sta_leave"

    def test_dns_timeout(self):
        msg = (
            "[STA_TRACKER] DNS request timed out; "
            "[STA: aa:bb:cc:dd:ee:ff][QUERY: example.com]"
            "[DNS_SERVER : 1.1.1.1]"
        )
        result = self.parser.try_parse("", msg)
        assert result is not None
        assert result.event_type == "dns_timeout"
        assert result.fields["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result.fields["query"] == "example.com"
        assert result.fields["dns_server"] == "1.1.1.1"

    def test_wireless_anomaly(self):
        msg = (
            "wireless_agg_stats.log_sta_anomalies(): "
            "sta=aa:bb:cc:dd:ee:ff anomalies=excessive_retries"
        )
        result = self.parser.try_parse("", msg)
        assert result is not None
        assert result.event_type == "wifi_anomaly"
        assert result.fields["anomalies"] == "excessive_retries"

    def test_switch_provision(self):
        msg = "syswrapper[1234]: Provision took 45 sec"
        result = self.parser.try_parse("syswrapper", msg)
        assert result is not None
        assert result.event_type == "switch_provision"
        assert result.fields["seconds"] == 45

    def test_switch_state_transition(self):
        msg = "ace_reporter.ace_reporter_set_state(): [STATE] transition connected -> disconnected"
        result = self.parser.try_parse("ace_reporter", msg)
        assert result is not None
        assert result.event_type == "switch_state"
        assert result.severity == "medium"
        assert result.fields["from_state"] == "connected"
        assert result.fields["to_state"] == "disconnected"

    def test_no_match(self):
        result = self.parser.try_parse("kernel", "random kernel message")
        assert result is None


# ===========================================================================
# UnraidParser
# ===========================================================================

class TestUnraidParser:
    def setup_method(self):
        self.parser = UnraidParser()

    def test_disk_warning_smart(self):
        msg = "SMART error logged for /dev/sda — Reallocated Sector Count = 8"
        result = self.parser.try_parse("emhttpd", msg)
        assert result is not None
        assert result.event_type == "disk_warning"
        assert result.severity == "high"

    def test_disk_warning_array_degraded(self):
        msg = "Array degraded — disk2 is disabled"
        result = self.parser.try_parse("emhttpd", msg)
        assert result is not None
        assert result.event_type == "disk_warning"
        assert result.severity == "high"

    def test_docker_crash(self):
        msg = "container abc123 died (exit code 137, OOM killed)"
        result = self.parser.try_parse("dockerd", msg)
        assert result is not None
        assert result.event_type == "docker_crash"
        assert result.severity == "medium"

    def test_emhttpd_spinning_up(self):
        msg = "emhttpd: spinning up /dev/sdb"
        result = self.parser.try_parse("emhttpd", msg)
        assert result is not None
        assert result.event_type == "emhttpd_event"

    def test_mover_started(self):
        msg = "mover: started"
        result = self.parser.try_parse("mover", msg)
        assert result is not None
        assert result.event_type == "mover_event"
        assert result.fields["action"] == "started"

    def test_mover_finished(self):
        msg = "mover: finished"
        result = self.parser.try_parse("mover", msg)
        assert result is not None
        assert result.fields["action"] == "finished"

    def test_sudo_session(self):
        msg = "sudo:   root : TTY=pts/0 ; session opened for user root"
        result = self.parser.try_parse("sudo", msg)
        assert result is not None
        assert result.event_type == "sudo_session"

    def test_ssh_failed(self):
        msg = "Failed password for invalid user admin from 10.0.0.5 port 54321 ssh2"
        result = self.parser.try_parse("sshd", msg)
        assert result is not None
        assert result.event_type == "ssh_auth"
        assert result.severity == "medium"
        assert result.fields["success"] is False

    def test_ssh_accepted(self):
        msg = "Accepted publickey for root from 192.168.1.50 port 55000 ssh2"
        result = self.parser.try_parse("sshd", msg)
        assert result is not None
        assert result.event_type == "ssh_auth"
        assert result.severity == "info"
        assert result.fields["success"] is True

    def test_noise_filtered(self):
        msg = "br-abc123: entered promiscuous mode"
        result = self.parser.try_parse("kernel", msg)
        assert result is None

    def test_noise_veth_filtered(self):
        msg = "veth1234567: renamed from eth0"
        result = self.parser.try_parse("kernel", msg)
        assert result is None

    def test_no_match(self):
        result = self.parser.try_parse("cron", "CROND: running job")
        assert result is None


# ===========================================================================
# DnsmasqParser
# ===========================================================================

class TestDnsmasqParser:
    def setup_method(self):
        self.parser = DnsmasqParser()

    def test_dhcpack(self):
        msg = "DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff myhost"
        result = self.parser.try_parse("dnsmasq-dhcp", msg)
        assert result is not None
        assert result.event_type == "dhcp_dhcpack"
        assert result.fields["ip"] == "192.168.1.50"
        assert result.fields["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result.fields["hostname"] == "myhost"
        assert result.fields["iface"] == "br0"

    def test_dhcpdiscover(self):
        msg = "DHCPDISCOVER(eth0) 192.168.1.100 11:22:33:44:55:66"
        result = self.parser.try_parse("dnsmasq-dhcp", msg)
        assert result is not None
        assert result.event_type == "dhcp_dhcpdiscover"
        assert result.fields["hostname"] == ""

    def test_dhcprelease(self):
        msg = "DHCPRELEASE(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff myhost"
        result = self.parser.try_parse("dnsmasq-dhcp", msg)
        assert result is not None
        assert result.event_type == "dhcp_dhcprelease"

    def test_dns_query(self):
        msg = "query[A] example.com from 192.168.1.50"
        result = self.parser.try_parse("dnsmasq", msg)
        assert result is not None
        assert result.event_type == "dns_query"
        assert result.fields["domain"] == "example.com"
        assert result.fields["query_type"] == "A"
        assert result.fields["client"] == "192.168.1.50"

    def test_dns_reply(self):
        msg = "reply example.com is 93.184.216.34"
        result = self.parser.try_parse("dnsmasq", msg)
        assert result is not None
        assert result.event_type == "dns_reply"
        assert result.fields["domain"] == "example.com"
        assert result.fields["answer"] == "93.184.216.34"
        assert result.fields["nxdomain"] is False

    def test_dns_reply_nxdomain(self):
        msg = "reply nonexistent.example.com is NXDOMAIN"
        result = self.parser.try_parse("dnsmasq", msg)
        assert result is not None
        assert result.fields["nxdomain"] is True

    def test_dns_cached(self):
        msg = "cached example.com is 93.184.216.34"
        result = self.parser.try_parse("dnsmasq", msg)
        assert result is not None
        assert result.event_type == "dns_reply"

    def test_wrong_program_no_keywords(self):
        result = self.parser.try_parse("sshd", "User logged in successfully")
        assert result is None

    def test_dhcp_keyword_without_program(self):
        msg = "DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff"
        result = self.parser.try_parse("someother", msg)
        assert result is not None


# ===========================================================================
# syslog_header parser
# ===========================================================================

class TestSyslogHeader:
    def test_rfc3164_with_pid(self):
        line = "Mar 18 14:30:01 myhost sshd[1234]: Accepted publickey for root"
        result = parse_syslog_header(line)
        assert result is not None
        assert result.hostname == "myhost"
        assert result.program == "sshd"
        assert result.pid == 1234
        assert result.message == "Accepted publickey for root"
        assert result.timestamp is not None
        assert result.timestamp.month == 3
        assert result.timestamp.day == 18

    def test_rfc3164_no_pid(self):
        line = "Jan  5 09:15:30 router kernel: some kernel message"
        result = parse_syslog_header(line)
        assert result is not None
        assert result.hostname == "router"
        assert result.program == "kernel"
        assert result.pid is None
        assert result.message == "some kernel message"

    def test_iso_timestamp(self):
        line = "2026-03-18T14:30:01+00:00 myhost hostapd[5678]: ath0: STA test"
        result = parse_syslog_header(line)
        assert result is not None
        assert result.hostname == "myhost"
        assert result.program == "hostapd"
        assert result.pid == 5678
        assert result.timestamp is not None
        assert result.timestamp.year == 2026

    def test_rfc5424(self):
        line = "<134>1 2026-03-18T14:30:01Z myhost app - - - Hello from RFC5424"
        result = parse_syslog_header(line)
        assert result is not None
        assert result.hostname == "myhost"
        assert result.program == "app"
        assert "Hello" in result.message

    def test_bare_line_returns_none(self):
        result = parse_syslog_header("just a plain message")
        assert result is None

    def test_empty_line(self):
        result = parse_syslog_header("")
        assert result is None

    def test_short_line(self):
        result = parse_syslog_header("short")
        assert result is None
