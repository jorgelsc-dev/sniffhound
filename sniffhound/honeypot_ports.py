"""Honeypot listener port sets - pulled out of honeypot.py so importing this
data (e.g. to seed the honeypot_listeners table in store.py) never pulls in
honeypot.py's module-level side effects.

honeypot.py opens a RotatingFileHandler for honeypot.log as soon as it's
imported (`LOGGER = _build_logger()`), which failed for the unprivileged web
process the moment store.py started importing `honeypot.COMMON_PORTS` just
to seed listener rows - the privileged capture process had always been the
only thing to import honeypot.py before, so a root-owned honeypot.log from
an earlier run was unreadable/unwritable to the unprivileged process. This
module has zero imports and zero side effects, so it's safe to import from
anywhere, including store.py's __init__ path.
"""

from __future__ import annotations

HTTP_TCP_PORTS = {80, 8000, 8080, 8888, 9200}
HTTPS_TCP_PORTS = {443, 8443, 9443}
FTP_PORTS = {21, 2121}
FTPS_PORTS = {990}
SMTP_PORTS = {25, 587, 2525}
SMTPS_PORTS = {465}
POP3_PORTS = {110}
POP3S_PORTS = {995}
IMAP_PORTS = {143}
IMAPS_PORTS = {993}
TELNET_PORTS = {23}
SSH_PORTS = {22}
MYSQL_PORTS = {3306}
POSTGRES_PORTS = {5432}
LDAP_PORTS = {389}
LDAPS_PORTS = {636}
REDIS_PORTS = {6379}
MEMCACHED_TCP_PORTS = {11211}
VNC_PORTS = {5900}
RDP_PORTS = {3389}
SMB_PORTS = {139, 445}
DNS_TCP_PORTS = {53}
MONGODB_PORTS = {27017}
MQTT_PORTS = {1883}
MQTTS_PORTS = {8883}
AMQP_PORTS = {5672}
AMQPS_PORTS = {5671}
RTSP_PORTS = {554}
GENERIC_TCP_PORTS = {2049}

TLS_TCP_PORTS = (
    HTTPS_TCP_PORTS
    | FTPS_PORTS
    | SMTPS_PORTS
    | POP3S_PORTS
    | IMAPS_PORTS
    | LDAPS_PORTS
    | MQTTS_PORTS
    | AMQPS_PORTS
)

DNS_UDP_PORTS = {53}
DHCP_UDP_PORTS = {67, 68}
TFTP_UDP_PORTS = {69}
NTP_UDP_PORTS = {123}
NETBIOS_UDP_PORTS = {137, 138}
SNMP_UDP_PORTS = {161}
IPSEC_UDP_PORTS = {500, 4500}
SYSLOG_UDP_PORTS = {514}
RIP_UDP_PORTS = {520}
RADIUS_UDP_PORTS = {1812, 1813}
SSDP_UDP_PORTS = {1900}
SIP_UDP_PORTS = {5060}
MDNS_UDP_PORTS = {5353}
MEMCACHED_UDP_PORTS = {11211}

COMMON_PORTS = {
    "tcp": sorted(
        HTTP_TCP_PORTS
        | HTTPS_TCP_PORTS
        | FTP_PORTS
        | FTPS_PORTS
        | SMTP_PORTS
        | SMTPS_PORTS
        | POP3_PORTS
        | POP3S_PORTS
        | IMAP_PORTS
        | IMAPS_PORTS
        | TELNET_PORTS
        | SSH_PORTS
        | MYSQL_PORTS
        | POSTGRES_PORTS
        | LDAP_PORTS
        | LDAPS_PORTS
        | REDIS_PORTS
        | MEMCACHED_TCP_PORTS
        | VNC_PORTS
        | RDP_PORTS
        | SMB_PORTS
        | DNS_TCP_PORTS
        | MONGODB_PORTS
        | MQTT_PORTS
        | MQTTS_PORTS
        | AMQP_PORTS
        | AMQPS_PORTS
        | RTSP_PORTS
        | GENERIC_TCP_PORTS
    ),
    "udp": sorted(
        DNS_UDP_PORTS
        | DHCP_UDP_PORTS
        | TFTP_UDP_PORTS
        | NTP_UDP_PORTS
        | NETBIOS_UDP_PORTS
        | SNMP_UDP_PORTS
        | IPSEC_UDP_PORTS
        | SYSLOG_UDP_PORTS
        | RIP_UDP_PORTS
        | RADIUS_UDP_PORTS
        | SSDP_UDP_PORTS
        | SIP_UDP_PORTS
        | MDNS_UDP_PORTS
        | MEMCACHED_UDP_PORTS
    ),
}
