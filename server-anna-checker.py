"""Verify public SMTP, IMAP and POP3 services without logging in.

Install DNS support with: py -m pip install dnspython
Run on Windows with: py mail_server_checker.py
"""

import csv
import socket
from collections import defaultdict
from collections import deque
import imaplib
import poplib
import re
import smtplib
import ssl
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

try:
    import dns.resolver
except ImportError:
    dns = None

TIMEOUT = 2
MAX_MX_HOSTS = 5
OUTPUT_COLUMNS = ["Domain", "Host", "Port", "SSL", "Security", "Verification"]
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


def get_input_file():
    while True:
        filename = input("Enter domain TXT file path: ").strip().strip('"')
        path = Path(filename).expanduser()
        if filename and path.is_file() and path.suffix.lower() == ".txt":
            return path
        print("[ERROR] Enter the path to an existing .txt file.")


def get_threads():
    while True:
        try:
            threads = int(input("Threads [100, max 200]: ").strip() or "100")
            if 1 <= threads <= 200:
                return threads
        except ValueError:
            pass
        print("[ERROR] Enter a whole number from 1 to 200.")


def clean_domain(line):
    value = line.strip()
    if not value or value.startswith("#"):
        return None
    try:
        host = urlsplit(value if "://" in value else "//" + value).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    return host if DOMAIN_RE.fullmatch(host) else None


def mx_hosts(domain):
    if dns is None:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        return [str(record.exchange).rstrip(".").lower()
                for record in sorted(answers, key=lambda r: r.preference)
                if str(record.exchange) != "."][:MAX_MX_HOSTS]
    except (dns.exception.DNSException, OSError):
        return []


def srv_targets(domain):
    """Use published mail service records when present."""
    if dns is None:
        return []
    services = (
        ("_submission._tcp", "smtp", 587),
        ("_submissions._tcp", "smtp", 465),
        ("_imaps._tcp", "imap", 993),
        ("_imap._tcp", "imap", 143),
        ("_pop3s._tcp", "pop3", 995),
        ("_pop3._tcp", "pop3", 110),
    )
    found = []
    for service, protocol, default_port in services:
        try:
            records = dns.resolver.resolve(f"{service}.{domain}", "SRV", lifetime=TIMEOUT)
            for record in sorted(records, key=lambda r: (r.priority, -r.weight))[:3]:
                host = str(record.target).rstrip(".").lower()
                port = int(record.port)
                # Check only the ports supported by the relevant protocol probe.
                if host and port == default_port:
                    found.append((protocol, host, port))
        except (dns.exception.DNSException, OSError):
            continue
    return found


def smtp_check(host, port):
    context = ssl.create_default_context()
    client = None
    try:
        if port == 465:
            client = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT, context=context)
            security = "implicit_tls"
        else:
            client = smtplib.SMTP(host, port, timeout=TIMEOUT)
            security = "none"
        code, _ = client.ehlo()
        if code != 250:
            return None
        if port != 465 and client.has_extn("starttls"):
            try:
                client.starttls(context=context)
                code, _ = client.ehlo()
                if code != 250:
                    return None
                security = "starttls"
            except (OSError, ssl.SSLError, smtplib.SMTPException):
                if port == 587:
                    return None
                # SMTP was verified by EHLO, but TLS could not be verified.
        elif port == 587:
            return None
        return security
    except (OSError, ssl.SSLError, smtplib.SMTPException):
        return None
    finally:
        if client is not None:
            client.close()


def imap_check(host, port):
    context = ssl.create_default_context()
    client = None
    try:
        if port == 993:
            client = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=TIMEOUT)
            security = "implicit_tls"
        else:
            client = imaplib.IMAP4(host, port, timeout=TIMEOUT)
            security = "none"
        status, data = client.capability()
        if status != "OK" or not data:
            return None
        if port == 143 and b"STARTTLS" in b" ".join(data).upper().split():
            client.starttls(ssl_context=context)
            status, data = client.capability()
            if status != "OK" or not data:
                return None
            security = "starttls"
        return security
    except (OSError, ssl.SSLError, imaplib.IMAP4.error):
        return None
    finally:
        if client is not None:
            try:
                client.logout()
            except (OSError, imaplib.IMAP4.error):
                pass


def pop3_check(host, port):
    context = ssl.create_default_context()
    client = None
    try:
        if port == 995:
            client = poplib.POP3_SSL(host, port, timeout=TIMEOUT, context=context)
            security = "implicit_tls"
        else:
            client = poplib.POP3(host, port, timeout=TIMEOUT)
            security = "none"
            try:
                capabilities = client.capa()
            except poplib.error_proto:
                capabilities = {}  # CAPA is optional in POP3.
            if "STLS" in capabilities:
                client.stls(context=context)
                security = "starttls"
        if not client.noop().upper().startswith(b"+OK"):
            return None
        return security
    except (OSError, ssl.SSLError, poplib.error_proto):
        return None
    finally:
        if client is not None:
            try:
                client.quit()
            except (OSError, poplib.error_proto):
                pass


ALL_SMTP_PREFIXES = ('activation-mail', 'activation-smtp', 'alert', 'alerts', 'alt-mail', 'alt-mx', 'alt-port', 'alt-smtp',
 'alt1.aspmx.l.google', 'alt2.aspmx.l.google', 'amazonses', 'anti-spam', 'anti-virus', 'antispam',
 'antivirus', 'api-email', 'api-mail', 'api-smtp', 'apiemail', 'apimail', 'apis', 'aspmx', 'aspmx.l.google',
 'aspmx1', 'aspmx2', 'aspmx3', 'auth-mail', 'auth-smtp', 'authenticated-mail', 'authenticated-smtp',
 'authmail', 'authsmtp', 'autoconfig', 'autodiscover', 'auto-mail', 'automail', 'backend-mail',
 'backend-smtp', 'backup-mail', 'backup-mail-relay-gw', 'backup-mx', 'backup-relay', 'backup-smtp',
 'backup-smtp-relay-gw', 'backuprelay', 'barracuda', 'billing-mail', 'billingmail', 'border-mail',
 'border-smtp', 'bounce-mail', 'bounce-smtp', 'bouncemail', 'bouncesmtp', 'brief', 'bulk-mail', 'bulk-smtp',
 'bulkmail', 'bulksmtp', 'campaign-mail', 'campaign-smtp', 'cdn-mail', 'cdn-mx', 'cdn-relay', 'cdn-smtp',
 'client', 'cloud-email', 'cloud-mail', 'cloud-mx', 'cloud-relay', 'cloud-smtp', 'cluster-mail',
 'cluster-smtp', 'clustermail', 'collector', 'confirm', 'confirm-mail', 'confirm-smtp', 'connect',
 'contact-mail', 'contactmail', 'container-mail', 'container-smtp', 'content-filter', 'contentfilter',
 'corp-mail', 'corp-smtp', 'corpmail', 'corpsmtp', 'correo', 'correio', 'courriel', 'cpanel', 'crm-mail',
 'crmmail', 'cron-mail', 'cronmail', 'custom-mail', 'custom-smtp', 'cyrus', 'cyrus-mail', 'datacenter-mail',
 'datacenter-smtp', 'dc-mail', 'dc-smtp', 'dc1-mail', 'dc1-smtp', 'dc2-mail', 'dc2-smtp', 'dedicated-mail',
 'dedicated-smtp', 'dev-mail', 'dev-smtp', 'directadmin', 'disaster-mail', 'disaster-smtp', 'dmz-mail',
 'dmz-smtp', 'docker-mail', 'docker-smtp', 'donotreply', 'dovecot', 'dovecot-mail', 'download', 'dr-mail',
 'dr-mx', 'dr-relay', 'dr-smtp', 'e-mail', 'e-mail-server', 'e-smtp', 'edge-mail', 'edge-mail-1',
 'edge-mail-2', 'edge-mx', 'edge-mx-1', 'edge-mx-2', 'edge-smtp', 'edge-smtp-1', 'edge-smtp-2', 'email',
 'email-api', 'email-gateway-1', 'email-gateway-2', 'email-gw', 'email-host', 'email-mail', 'email-mx',
 'email-relay', 'email-secure', 'email-security', 'email-server', 'email-smtp', 'email.mail', 'email.smtp',
 'email01', 'email02', 'email1', 'email2', 'emailapi', 'emailer', 'emailer1', 'emailer2', 'emailgw',
 'emailgw1', 'emailgw2', 'emailhost', 'emailmx', 'emailrelay', 'emailserver', 'emailsmtp', 'epost', 'esmtp',
 'esmtp-relay', 'esmtp1', 'esmtp2', 'exchange', 'exchange-auth', 'exchange-mail', 'exchange-mx',
 'exchange-relay', 'exchange-secure', 'exchange-smtp', 'exchange-ssl', 'exchange.corp', 'exchange.internal',
 'exchange.mail', 'exchange01', 'exchange02', 'exchange1', 'exchange2', 'exchangemail', 'exchangemx',
 'exchangerelay', 'exchangesmtp', 'exch', 'exch01', 'exch02', 'exch1', 'exch2', 'exim', 'exim-smtp', 'exim4',
 'failover-mail', 'failover-mx', 'failover-smtp', 'fallback-mail', 'fallback-mx', 'fallback-smtp',
 'fast-mail', 'fast-smtp', 'fastmail', 'fastsmtp', 'fetch', 'fetchmail', 'forward-mail', 'forward-mail-1',
 'forward-mail-2', 'forwarder-mail', 'forwarder-smtp', 'forwardersmtp', 'forwardmail', 'fortimail',
 'front-mail', 'front-smtp', 'frontend-mail', 'frontend-smtp', 'gateway', 'getmail', 'gmail', 'googlemail',
 'gw', 'gw-mail', 'gw-mail-smtp-relay', 'gw-relay', 'gw-smtp', 'gw-smtp-mail-relay', 'gw01', 'gw02', 'gw1',
 'gw2', 'gwmail', 'gwrelay', 'gwsmtp', 'haraka', 'helpdesk-mail', 'helpdeskmail', 'hosted-mail',
 'hosted-smtp', 'hotmail', 'hr-mail', 'hrmail', 'icloud', 'imap', 'imap-mail', 'imap1', 'imap2', 'imap4',
 'imapd', 'imapmail', 'imaps', 'in', 'in-mail', 'in-mail-relay', 'in-mail-smtp-relay', 'in-relay', 'in-smtp',
 'in-smtp-relay', 'in-stream', 'in01', 'in1', 'in2', 'inbound', 'inbound-mail', 'inbound-relay', 'inbound1',
 'inbound2', 'inboundmail', 'inboundrelay', 'inbox', 'incoming', 'incoming-mail', 'incoming-smtp',
 'incomingsmtp', 'info-mail', 'infomail', 'internal-mail', 'internal-smtp', 'internalmail', 'internalsmtp',
 'invoice-mail', 'invoicemail', 'ironport', 'ispconfig', 'k8s-mail', 'k8s-smtp', 'lb-mail', 'lb-smtp',
 'lb1-mail', 'lb2-mail', 'lbmail', 'login-mail', 'login-smtp', 'm-mail', 'm-smtp', 'mail', 'mail-agent',
 'mail-alt', 'mail-alternate', 'mail-api', 'mail-app', 'mail-asia', 'mail-au', 'mail-auth', 'mail-aws',
 'mail-az1', 'mail-az2', 'mail-azure', 'mail-biz', 'mail-box', 'mail-ca', 'mail-client', 'mail-cloud',
 'mail-de', 'mail-dev', 'mail-drop', 'mail-east', 'mail-edge', 'mail-email', 'mail-eu', 'mail-filter',
 'mail-fr', 'mail-gate', 'mail-gateway', 'mail-gcp', 'mail-gw', 'mail-gw1', 'mail-gw2', 'mail-host',
 'mail-hosted', 'mail-hosted-1', 'mail-hosted-2', 'mail-hosting', 'mail-hub', 'mail-in', 'mail-in-relay-smtp',
 'mail-in1', 'mail-in2', 'mail-inbound', 'mail-internal', 'mail-io', 'mail-jp', 'mail-link', 'mail-m',
 'mail-mx', 'mail-mx-in', 'mail-mx-out', 'mail-net', 'mail-nyc', 'mail-office', 'mail-out',
 'mail-out-relay-smtp', 'mail-out1', 'mail-out2', 'mail-outbound', 'mail-post', 'mail-prod', 'mail-proxy',
 'mail-queue', 'mail-recv', 'mail-relay', 'mail-relay-out', 'mail-relay-smtp-mx', 'mail-relay1',
 'mail-relay2', 'mail-s', 'mail-scan', 'mail-scanner', 'mail-secure', 'mail-send', 'mail-serv',
 'mail-service', 'mail-smtp', 'mail-smtp-in', 'mail-smtp-mx-relay', 'mail-smtp-out', 'mail-smtp-relay-gw',
 'mail-ssl', 'mail-staging', 'mail-submission', 'mail-svc', 'mail-test', 'mail-tls', 'mail-uk', 'mail-us',
 'mail-web', 'mail-west', 'mail.biz', 'mail.cloud', 'mail.corp', 'mail.dmz', 'mail.email', 'mail.host',
 'mail.internal', 'mail.io', 'mail.link', 'mail.local', 'mail.msg', 'mail.mx', 'mail.net', 'mail.office',
 'mail.post', 'mail.relay', 'mail.smtp', 'mail.web', 'mail01', 'mail02', 'mail03', 'mail04', 'mail05',
 'mail06', 'mail07', 'mail08', 'mail09', 'mail1', 'mail10', 'mail11', 'mail12', 'mail13', 'mail14', 'mail16',
 'mail17', 'mail18', 'mail19', 'mail2', 'mail20', 'mail25', 'mail3', 'mail3a', 'mail3b', 'mail4', 'mail465',
 'mail5', 'mail587', 'mail6', 'mail7', 'mail8', 'mail9', 'mail1.mail', 'mail2.mail', 'mailagent', 'mailapp',
 'mailauth', 'mailbox', 'mailchimp', 'mailclient', 'maildaemon', 'maildrop', 'maildrop1', 'maildrop2',
 'mailer', 'mailer-daemon', 'mailer1', 'mailer2', 'mailfilter', 'mailgate', 'mailgateway', 'mailgw',
 'mailgun', 'mailhost', 'mailhub', 'mailin', 'maillist', 'mailmx', 'mailout', 'mailproxy', 'mailq',
 'mailqueue', 'mailrecv', 'mailrelay', 'mailscan', 'mailscanner', 'mailsecure', 'mailsend', 'mailserv',
 'mailservice', 'mailserver', 'mailsrv', 'mailsrv1', 'mailsrv2', 'mailssl', 'mailsvc', 'mailtls',
 'managed-mail', 'managed-smtp', 'mandrill', 'marketing-mail', 'marketing-smtp', 'marketingsmtp', 'mass-mail',
 'massmail', 'mcafee', 'mda', 'message', 'message-filter', 'message-gateway', 'messages', 'messagefilter',
 'messagegateway', 'messagelabs', 'messaging', 'messaging-server', 'messagingserver', 'microsoft', 'mimecast',
 'mirror-mail', 'mirror-mx', 'mirror-smtp', 'msg', 'msg-gw', 'msg-server', 'msggw', 'msgserver', 'mta',
 'mta-1', 'mta-2', 'mta-3', 'mta-sts', 'mta01', 'mta02', 'mta03', 'mta1', 'mta2', 'mta3', 'mx', 'mx-asia',
 'mx-auth', 'mx-backup', 'mx-cloud', 'mx-corp', 'mx-e', 'mx-east', 'mx-edge', 'mx-edge-1', 'mx-edge-2',
 'mx-email', 'mx-eu', 'mx-filter', 'mx-gateway', 'mx-gateway-1', 'mx-gateway-2', 'mx-gw', 'mx-gw1', 'mx-gw2',
 'mx-host', 'mx-in', 'mx-in1', 'mx-in2', 'mx-inbound', 'mx-internal', 'mx-io', 'mx-m', 'mx-mail',
 'mx-mail-smtp-relay', 'mx-out', 'mx-out1', 'mx-out2', 'mx-outbound', 'mx-proxy', 'mx-relay', 'mx-relay-in',
 'mx-relay-out', 'mx-relay-smtp-mail', 'mx-s', 'mx-secure', 'mx-server', 'mx-ssl', 'mx-us', 'mx-west',
 'mx.cloud', 'mx.corp', 'mx.email', 'mx.internal', 'mx.io', 'mx.mail', 'mx.relay', 'mx.smtp', 'mx01', 'mx02',
 'mx03', 'mx04', 'mx05', 'mx06', 'mx07', 'mx08', 'mx09', 'mx1', 'mx10', 'mx11', 'mx12', 'mx13', 'mx14',
 'mx15', 'mx16', 'mx17', 'mx18', 'mx19', 'mx2', 'mx20', 'mx25', 'mx3', 'mx3a', 'mx3b', 'mx4', 'mx465', 'mx5',
 'mx587', 'mx6', 'mx7', 'mx8', 'mx9', 'mx1.mail', 'mx2.mail', 'mxauth', 'mxbackup', 'mxfilter', 'mxgateway',
 'mxgw', 'mxhost', 'mxin', 'mxout', 'mxproxy', 'mxrelay', 'mxsecure', 'mxserver', 'mxs15', 'mxssl',
 'newsletter', 'newsletter-mail', 'node-mail', 'node1-mail', 'node2-mail', 'noreply', 'no-reply',
 'notification', 'notifications', 'notify', 'office365', 'opensmtpd', 'out', 'out-mail', 'out-mail-relay',
 'out-mail-smtp-relay', 'out-relay', 'out-smtp', 'out-smtp-relay', 'out-stream', 'out1', 'out2', 'outbound',
 'outbound-mail', 'outbound-relay', 'outbound-smtp', 'outbound1', 'outbound2', 'outboundmail',
 'outboundrelay', 'outbox', 'outgoing', 'outgoing-mail', 'outgoing-smtp', 'outgoingsmtp', 'outlook',
 'outmail', 'outrelay', 'outsmtp', 'owa', 'password-mail', 'password-smtp', 'perimeter-mail',
 'perimeter-smtp', 'plesk', 'poczta', 'pod-mail', 'pod-smtp', 'pool-mail', 'pool-smtp', 'pop', 'pop-mail',
 'pop-smtp', 'pop1', 'pop2', 'pop3', 'pop3s', 'popd', 'popmail', 'pops', 'post', 'post-box', 'post-mail',
 'post-relay', 'post-smtp', 'posta', 'postbox', 'poste', 'postfix', 'postfix-mail', 'postfix-smtp',
 'postfix1', 'postfix2', 'postmail', 'postmaster', 'postmark', 'postrelay', 'postsmtp', 'primary-mail-relay',
 'primary-smtp-relay', 'prod-mail', 'prod-smtp', 'proofpoint', 'proton', 'protonmail', 'proxy-mail',
 'proxy-mx', 'proxy-relay', 'proxy-smtp', 'push', 'push-mail', 'pushmail', 'qmail', 'qmail-smtp',
 'quick-mail', 'quick-smtp', 'quickmail', 'quicksmtp', 'rapid-mail', 'rapid-smtp', 'rapidmail', 'rapidsmtp',
 'receive', 'receiver', 'receiving', 'recover-mail', 'recovery-smtp', 'redirect-mail', 'redirect-smtp',
 'redirectmail', 'relay', 'relay-auth', 'relay-corp', 'relay-dmz', 'relay-edge', 'relay-email',
 'relay-gateway-1', 'relay-gateway-2', 'relay-gw', 'relay-gw-mail-smtp', 'relay-host', 'relay-in',
 'relay-in-mail-smtp', 'relay-in1', 'relay-in2', 'relay-internal', 'relay-mail', 'relay-mail-in',
 'relay-mail-out', 'relay-mail-smtp-gw', 'relay-mx', 'relay-mx-mail-smtp', 'relay-mx-smtp-mail', 'relay-net',
 'relay-out', 'relay-out-mail-smtp', 'relay-out1', 'relay-out2', 'relay-secure', 'relay-smtp', 'relay-ssl',
 'relay.corp', 'relay.dmz', 'relay.email', 'relay.host', 'relay.internal', 'relay.mail', 'relay.net',
 'relay.smtp', 'relay01', 'relay02', 'relay03', 'relay1', 'relay10', 'relay1a', 'relay1b', 'relay2',
 'relay2a', 'relay2b', 'relay3', 'relay4', 'relay5', 'relay6', 'relay7', 'relay8', 'relay9', 'relay1.mail',
 'relay2.mail', 'relayauth', 'relaygw', 'relayin', 'relaymail', 'relaymx', 'relayout', 'relaysecure',
 'relayserver', 'relaysmtp', 'relayssl', 'replica-mail', 'replica-mx', 'replica-smtp', 'reseller-mail',
 'reseller-smtp', 'reset-mail', 'reset-smtp', 'roundcube', 'saas-mail', 'saas-smtp', 'sales-mail',
 'salesmail', 'secondary-mail', 'secondary-mail-relay', 'secondary-mx', 'secondary-smtp',
 'secondary-smtp-relay', 'secure-email-relay', 'secure-mail', 'secure-mail-relay', 'secure-mx-relay',
 'secure-relay-email', 'secure-relay-mail', 'secure-relay-mx', 'secure-relay-smtp', 'secure-smtp',
 'secure-smtp-relay', 'secure1-mail', 'secure1-mx', 'secure1-smtp', 'secure2-mail', 'secure2-mx',
 'secure2-smtp', 'securemail', 'securesmtp', 'security-gateway', 'securitygateway', 'send', 'send-mail',
 'send-out', 'send01', 'send02', 'send1', 'send2', 'sender', 'sender-mail', 'sendgrid', 'sending', 'sendmail',
 'sendmail-server', 'sendout', 'ses', 'shard-mail', 'shard1-mail', 'shard2-mail', 'shared-mail',
 'shared-smtp', 'simple-mail', 'simple-mx', 'simple-smtp', 'simplemail', 'simplemx', 'simplesmtp',
 'smart-host', 'smarthost', 'smtp', 'smtp-ae', 'smtp-alt', 'smtp-alternate', 'smtp-ams', 'smtp-api',
 'smtp-ar', 'smtp-asia', 'smtp-at', 'smtp-au', 'smtp-auth', 'smtp-aws', 'smtp-az1', 'smtp-az2', 'smtp-azure',
 'smtp-be', 'smtp-biz', 'smtp-border', 'smtp-br', 'smtp-ca', 'smtp-central', 'smtp-ch', 'smtp-cl',
 'smtp-client', 'smtp-cloud', 'smtp-cn', 'smtp-co', 'smtp-custom', 'smtp-de', 'smtp-dev', 'smtp-dk',
 'smtp-dmz', 'smtp-east', 'smtp-edge', 'smtp-email', 'smtp-es', 'smtp-eu', 'smtp-eu1', 'smtp-eu2',
 'smtp-filter', 'smtp-fi', 'smtp-fra', 'smtp-fr', 'smtp-gateway', 'smtp-gcp', 'smtp-gr', 'smtp-gw',
 'smtp-gw1', 'smtp-gw2', 'smtp-hk', 'smtp-host', 'smtp-hosted', 'smtp-hosted-1', 'smtp-hosted-2',
 'smtp-hosting', 'smtp-id', 'smtp-il', 'smtp-in', 'smtp-in-relay-mail', 'smtp-in1', 'smtp-in2',
 'smtp-inbound', 'smtp-internal', 'smtp-io', 'smtp-it', 'smtp-jp', 'smtp-kr', 'smtp-link', 'smtp-lon',
 'smtp-m', 'smtp-mail', 'smtp-mail-in', 'smtp-mail-mx-relay', 'smtp-mail-out', 'smtp-mail-relay-gw',
 'smtp-my', 'smtp-mx', 'smtp-mx-in', 'smtp-mx-out', 'smtp-net', 'smtp-nl', 'smtp-no', 'smtp-north',
 'smtp-nyc', 'smtp-nz', 'smtp-office', 'smtp-out', 'smtp-out-relay-mail', 'smtp-out1', 'smtp-out2',
 'smtp-outbound', 'smtp-par', 'smtp-pe', 'smtp-ph', 'smtp-pl', 'smtp-prod', 'smtp-proxy', 'smtp-pt',
 'smtp-relay', 'smtp-relay-mail-mx', 'smtp-relay-out', 'smtp-relay1', 'smtp-relay2', 'smtp-ru', 'smtp-s',
 'smtp-sa', 'smtp-scan', 'smtp-se', 'smtp-secure', 'smtp-send', 'smtp-server', 'smtp-services', 'smtp-sfo',
 'smtp-sg', 'smtp-solutions', 'smtp-south', 'smtp-ssl', 'smtp-staging', 'smtp-systems', 'smtp-tech',
 'smtp-test', 'smtp-th', 'smtp-tls', 'smtp-tok', 'smtp-tr', 'smtp-tw', 'smtp-uk', 'smtp-us', 'smtp-us1',
 'smtp-us2', 'smtp-vn', 'smtp-web', 'smtp-west', 'smtp-za', 'smtp.amazonses', 'smtp.aol', 'smtp.biz',
 'smtp.cloud', 'smtp.corp', 'smtp.dev', 'smtp.dmz', 'smtp.email', 'smtp.gmail', 'smtp.host', 'smtp.icloud',
 'smtp.internal', 'smtp.io', 'smtp.link', 'smtp.live', 'smtp.local', 'smtp.mail', 'smtp.mail.me',
 'smtp.mail.yahoo', 'smtp.mailgun', 'smtp.mailserver', 'smtp.mandrill', 'smtp.mess', 'smtp.msg', 'smtp.net',
 'smtp.office', 'smtp.office365', 'smtp.par', 'smtp.post', 'smtp.postmark', 'smtp.prod', 'smtp.relay',
 'smtp.secureserver', 'smtp.secureserver.net', 'smtp.server', 'smtp.services', 'smtp.solutions',
 'smtp.sparkpost', 'smtp.staging', 'smtp.systems', 'smtp.tech', 'smtp.test', 'smtp.web', 'smtp.zoho',
 'smtp01', 'smtp02', 'smtp03', 'smtp04', 'smtp05', 'smtp06', 'smtp07', 'smtp08', 'smtp09', 'smtp1', 'smtp10',
 'smtp11', 'smtp12', 'smtp13', 'smtp14', 'smtp15', 'smtp16', 'smtp17', 'smtp18', 'smtp19', 'smtp2', 'smtp20',
 'smtp2go', 'smtp3', 'smtp3a', 'smtp3b', 'smtp4', 'smtp465', 'smtp5', 'smtp587', 'smtp6', 'smtp7', 'smtp8',
 'smtp9', 'smtp1.mail', 'smtp2.mail', 'smtpalt', 'smtpapi', 'smtpauth', 'smtpclient', 'smtpd', 'smtpfilter',
 'smtpgateway', 'smtpgw', 'smtpin', 'smtpmail', 'smtpmx', 'smtpout', 'smtpprod', 'smtpproxy', 'smtprelay',
 'smtps', 'smtps-mail', 'smtps-relay', 'smtps1', 'smtps2', 'smtpsend', 'smtpserver', 'smtpsrv', 'smtpsrv1',
 'smtpsrv2', 'smtpssl', 'smtptls', 'spam-filter', 'spamfilter', 'sparkpost', 'speed-mail', 'speed-smtp',
 'speedmail', 'speedsmtp', 'squirrelmail', 'stage-mail', 'stage-smtp', 'standby-mail', 'standby-mx',
 'standby-smtp', 'starttls', 'sts', 'submission', 'submit', 'support-mail', 'supportmail', 'symantec',
 'system-mail', 'system-smtp', 'systemmail', 'systemsmtp', 'test-mail', 'test-smtp', 'tls-mail', 'tls-mx',
 'tls-relay', 'tls-smtp', 'tlsmail', 'tlssmtp', 'transactional', 'transactional-mail', 'transactional-smtp',
 'transport', 'trendmicro', 'turbo-mail', 'turbo-smtp', 'turbomail', 'turbosmtp', 'verify', 'verify-mail',
 'verify-smtp', 'virus-filter', 'virusfilter', 'vps-mail', 'vps-smtp', 'webmail', 'webmail1', 'webmail2',
 'welcome-mail', 'welcome-smtp', 'whm', 'yahoo', 'yandex', 'zimbra', 'zoho')

ALL_IMAP_PREFIXES = ('access', 'cpanel', 'cyrus', 'dovecot', 'email', 'email-host', 'email-server', 'email01', 'email1', 'email2',
 'emailhost', 'emailserver', 'exchange', 'exchange01', 'exchange1', 'imap', 'imap-mail', 'imap-ssl', 'imap01',
 'imap02', 'imap1', 'imap2', 'imap3', 'imap4', 'imapmail', 'imaps', 'in', 'in-mail', 'inbound',
 'inbound-mail', 'inbox', 'incoming', 'incoming-imap', 'incoming-mail', 'incomingmail', 'mail', 'mail-client',
 'mail-host', 'mail-imap', 'mail-secure', 'mail-server', 'mail-ssl', 'mail01', 'mail02', 'mail1', 'mail2',
 'mail3', 'mailbox', 'mailclient', 'mailhost', 'mailserver', 'mailsrv', 'mx', 'mx1', 'mx2', 'owa', 'plesk',
 'postbox', 'receive', 'recv', 'roundcube', 'secure-imap', 'secure-mail', 'secureimap', 'securemail',
 'ssl-imap', 'webmail', 'webmail1', 'webmail2')

ALL_POP3_PREFIXES = ('access', 'cpanel', 'cyrus', 'dovecot', 'email', 'email-host', 'email-server', 'email01', 'email02',
 'email1', 'email2', 'emailhost', 'emailserver', 'exchange', 'exchange01', 'exchange1', 'in', 'in-mail',
 'inbox', 'inbound', 'inbound-mail', 'incoming', 'incoming-mail', 'incoming-pop', 'incoming-pop3',
 'incomingmail', 'mail', 'mail-client', 'mail-host', 'mail-pop', 'mail-pop3', 'mail-secure', 'mail-server',
 'mail-ssl', 'mail01', 'mail02', 'mail1', 'mail2', 'mail3', 'mailbox', 'mailclient', 'mailhost', 'mailserver',
 'mailsrv', 'mx', 'mx1', 'mx2', 'plesk', 'pop', 'pop-in', 'pop-mail', 'pop-server', 'pop-ssl', 'pop.mail',
 'pop01', 'pop02', 'pop1', 'pop2', 'pop3', 'pop3-01', 'pop3-02', 'pop3-in', 'pop3-mail', 'pop3-server',
 'pop3-ssl', 'pop31', 'pop32', 'pop3d', 'pop3mail', 'pop3s', 'pop4', 'popd', 'popmail', 'pops', 'postbox',
 'qpopper', 'receive', 'recv', 'roundcube', 'secure-mail', 'secure-pop', 'secure-pop3', 'securemail',
 'securepop', 'securepop3', 'ssl-mail', 'ssl-pop', 'ssl-pop3', 'sslpop', 'sslpop3', 'webmail', 'webmail1',
 'webmail2')

FAST_SMTP_PREFIXES = ("smtp", "mail", "submission", "outgoing", "email", "relay", "mx", "smtp1", "mail1")
FAST_IMAP_PREFIXES = ("imap", "mail", "imap4", "email", "incoming", "mail1")
FAST_POP3_PREFIXES = ("pop", "pop3", "mail", "email", "incoming", "mail1")
CHECKERS = {"smtp": smtp_check, "imap": imap_check, "pop3": pop3_check}


def get_mode():
    while True:
        mode = input("Scan mode [fast/all] (default fast): ").strip().lower() or "fast"
        if mode in ("fast", "all"):
            return mode
        print("[ERROR] Enter fast or all.")


def discover_hosts(domain, mode):
    """Build host -> protocol/port mapping, keeping DNS and socket work separate."""
    hosts = defaultdict(list)

    def add(protocol, host, port):
        if DOMAIN_RE.fullmatch(host) and (protocol, port) not in hosts[host]:
            hosts[host].append((protocol, port))

    for host in mx_hosts(domain):
        add("smtp", host, 25)  # MX describes inbound SMTP only.
    if mode == "all":
        smtp, imap, pop = ALL_SMTP_PREFIXES, ALL_IMAP_PREFIXES, ALL_POP3_PREFIXES
        smtp_ports = (465, 587, 25, 2525, 26)
    else:
        smtp, imap, pop = FAST_SMTP_PREFIXES, FAST_IMAP_PREFIXES, FAST_POP3_PREFIXES
        smtp_ports = (465, 587, 25)

    # The bare domain is also worth checking, especially for smaller providers.
    for protocol, ports in (("smtp", smtp_ports), ("imap", (993, 143)),
                            ("pop3", (995, 110))):
        for port in ports:
            add(protocol, domain, port)
    for prefix in smtp:
        for port in smtp_ports:
            add("smtp", f"{prefix}.{domain}", port)
    for prefix in imap:
        for port in (993, 143):
            add("imap", f"{prefix}.{domain}", port)
    for prefix in pop:
        for port in (995, 110):
            add("pop3", f"{prefix}.{domain}", port)
    if mode == "all":
        for protocol, host, port in srv_targets(domain):
            add(protocol, host, port)
    return hosts


def resolves(host):
    """One DNS resolution per hostname, before testing its candidate ports."""
    if dns is not None:
        try:
            dns.resolver.resolve(host, "A", lifetime=TIMEOUT)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.exception.DNSException:
            try:
                dns.resolver.resolve(host, "AAAA", lifetime=TIMEOUT)
                return True
            except dns.exception.DNSException:
                return False
    try:
        return bool(socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
    except (OSError, UnicodeError):
        return False


def check_endpoint(domain, protocol, host, port):
    security = CHECKERS[protocol](host, port)
    if security is None:
        return None
    return (domain, host, port, int(security != "none"), security, "protocol_handshake")


def main():
    input_file = get_input_file()
    mode = get_mode()
    threads = get_threads()
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    outputs = {name: Path(f"{name}({stamp}).csv") for name in ("smtp", "imap", "pop3")}
    totals = {name: 0 for name in outputs}
    read_count = domains_discovered = hosts_resolved = endpoints_checked = 0
    print(f"Input: {input_file} | Mode: {mode} | Threads: {threads}")
    with open(input_file, encoding="utf-8-sig", errors="ignore") as source, \
         open(outputs["smtp"], "w", newline="", encoding="utf-8-sig") as smtp_file, \
         open(outputs["imap"], "w", newline="", encoding="utf-8-sig") as imap_file, \
         open(outputs["pop3"], "w", newline="", encoding="utf-8-sig") as pop_file, \
         ThreadPoolExecutor(max_workers=threads) as executor:
        writers = {name: csv.writer(file) for name, file in
                   (("smtp", smtp_file), ("imap", imap_file), ("pop3", pop_file))}
        for writer in writers.values():
            writer.writerow(OUTPUT_COLUMNS)
        pending = {}  # Future -> (job, domain, host, ports)
        host_queue = deque()
        endpoint_queue = deque()
        input_done = False
        active_discoveries = 0
        max_pending = max(threads * 8, 200)

        while pending or host_queue or endpoint_queue or not input_done:
            while endpoint_queue and len(pending) < max_pending:
                domain, protocol, host, port = endpoint_queue.popleft()
                future = executor.submit(check_endpoint, domain, protocol, host, port)
                pending[future] = ("endpoint", domain, host, protocol)
            while host_queue and len(pending) < max_pending and len(endpoint_queue) < max_pending:
                domain, host, ports = host_queue.popleft()
                future = executor.submit(resolves, host)
                pending[future] = ("dns", domain, host, ports)
            while (not input_done and active_discoveries < max(1, threads // 20)
                   and len(pending) < max_pending and len(host_queue) < max_pending):
                line = source.readline()
                if not line:
                    input_done = True
                    break
                read_count += 1
                domain = clean_domain(line)
                if domain:
                    future = executor.submit(discover_hosts, domain, mode)
                    pending[future] = ("discovery", domain, "", ())
                    active_discoveries += 1
            if not pending:
                continue
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                job, domain, host, info = pending.pop(future)
                try:
                    result = future.result()
                except Exception as error:
                    print(f"\n[ERROR] {job} failed for {host or domain}: {error}")
                    result = None
                if job == "discovery":
                    active_discoveries -= 1
                    domains_discovered += 1
                    if result is not None:
                        host_queue.extend((domain, name, ports) for name, ports in result.items())
                elif job == "dns":
                    if result:
                        hosts_resolved += 1
                        endpoint_queue.extend((domain, protocol, host, port) for protocol, port in info)
                else:
                    endpoints_checked += 1
                    if result is not None:
                        writers[info].writerow(result)
                        totals[info] += 1
                    if endpoints_checked % 100 == 0:
                        print(f"Probed {endpoints_checked:,} | Domains {domains_discovered:,} | "
                              f"SMTP {totals['smtp']:,} | IMAP {totals['imap']:,} | "
                              f"POP3 {totals['pop3']:,}", end="\r", flush=True)
    print(f"\nDone. Read {read_count:,} lines; processed {domains_discovered:,} domains; "
          f"resolved {hosts_resolved:,} hosts; probed {endpoints_checked:,} endpoints.")
    for name, path in outputs.items():
        print(f"{name.upper()}: {totals[name]:,} verified endpoints -> {path}")
    if dns is None:
        print("Tip: install dnspython for MX and SRV discovery: py -m pip install dnspython")


if __name__ == "__main__":
    main()
