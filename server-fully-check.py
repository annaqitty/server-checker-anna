import asyncio
import csv
import sys
from pathlib import Path
from typing import Set, Tuple, List, Optional, Iterator
import socket

# ==========================================================
# OPTIONAL: uvloop for 2-4x extra speed
# ==========================================================
try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

# ==========================================================
# CONFIG
# ==========================================================

TIMEOUT = 1
CONCURRENCY = 10000  # Max concurrent TCP connections (was 200 threads)
BATCH_SIZE = 1000   # Domains to process in parallel
WRITE_BUFFER = 1000 # Flush CSV every N rows

SMTP_OUTPUT = "smtp-spaceship.csv"
IMAP_OUTPUT = "imap-spaceship.csv"
POP3_OUTPUT = "pop3-spaceship.csv"

# ==========================================================
# MAIL SERVER PATTERNS (Optimized as tuples)
# ==========================================================

SMTP_SERVERS = (
    ('smtp1.{}', 25, 0), ('smtp2.{}', 25, 0), ('smtp3.{}', 25, 0),
    ('smtp4.{}', 587, 1), ('smtp4.{}', 25, 0), ('smtp5.{}', 25, 0),
    ('smtp6.{}', 25, 0), ('smtp7.{}', 25, 0), ('smtp8.{}', 25, 0),
    ('smtp9.{}', 25, 0), ('smtp10.{}', 25, 0), ('smtp11.{}', 25, 0),
    ('smtp12.{}', 25, 0), ('smtp13.{}', 25, 0), ('smtp14.{}', 25, 0),
    ('smtp16.{}', 25, 0), ('smtp17.{}', 25, 0), ('smtp18.{}', 25, 0),
    ('smtp20.{}', 25, 0), ('mail1.{}', 25, 0), ('mail2.{}', 25, 0),
    ('mail3.{}', 25, 0), ('mail4.{}', 25, 0), ('mail5.{}', 25, 0),
    ('mail6.{}', 25, 0), ('mail8.{}', 25, 0), ('mail9.{}', 25, 0),
    ('mail10.{}', 25, 0), ('mail11.{}', 25, 0), ('mail12.{}', 25, 0),
    ('mail13.{}', 25, 0), ('mail14.{}', 25, 0), ('mail16.{}', 25, 0),
    ('mail17.{}', 25, 0), ('mail18.{}', 25, 0), ('mail20.{}', 25, 0),
    ('mx1.{}', 25, 0), ('mx2.{}', 25, 0), ('mx3.{}', 25, 0),
    ('mx4.{}', 25, 0), ('mx5.{}', 25, 0), ('mx7.{}', 25, 0),
    ('mx8.{}', 25, 0), ('mx9.{}', 25, 0), ('mx11.{}', 25, 0),
    ('mx12.{}', 25, 0), ('mx13.{}', 25, 0), ('mx15.{}', 25, 0),
    ('mx16.{}', 25, 0), ('mx17.{}', 25, 0), ('mx19.{}', 25, 0),
    ('mx20.{}', 25, 0), ('mx01.{}', 25, 0), ('mx02.{}', 25, 0),
    ('mx03.{}', 25, 0), ('mx04.{}', 25, 0), ('mx05.{}', 25, 0),
    ('mx06.{}', 25, 0), ('mx08.{}', 25, 0), ('mx09.{}', 25, 0),
    ('mx14.{}', 25, 0), ('mx18.{}', 25, 0), ('smtp.{}', 25, 0),
    ('smtp.{}', 465, 1), ('smtp.{}', 587, 1), ('smtp.{}', 2525, 0),
    ('smtp.{}', 993, 1), ('smtp.{}', 995, 1), ('smtp.{}', 110, 0),
    ('smtp.{}', 143, 0), ('smtp.{}', 10025, 0), ('mail.{}', 25, 0),
    ('mail.{}', 465, 1), ('mail.{}', 587, 1), ('mail.{}', 2525, 0),
    ('mail.{}', 993, 1), ('mail.{}', 995, 1), ('mail.{}', 110, 0),
    ('mail.{}', 143, 0), ('mail.{}', 10025, 0), ('mx.{}', 25, 0),
    ('mx.{}', 465, 1), ('mx.{}', 587, 1), ('mx.{}', 2525, 0),
    ('mx.{}', 10025, 0), ('email.{}', 25, 0), ('email.{}', 465, 1),
    ('email.{}', 587, 1), ('email.{}', 2525, 0), ('relay.{}', 25, 0),
    ('relay.{}', 465, 1), ('relay.{}', 587, 1), ('relay.{}', 2525, 0),
    ('relay.{}', 10025, 0), ('smtp15.{}', 25, 0), ('smtp19.{}', 25, 0),
    ('mail7.{}', 25, 0), ('mail19.{}', 25, 0), ('mx6.{}', 25, 0),
    ('mx10.{}', 25, 0), ('mxs15.{}', 25, 0), ('mx07.{}', 25, 0),
    ('smtp-relay.{}', 25, 0), ('smtprelay.{}', 25, 0), ('mail-relay.{}', 25, 0),
    ('mailrelay.{}', 25, 0), ('smtp-mail.{}', 587, 1), ('smtp-mail.{}', 25, 0),
    ('smtpmail.{}', 25, 0), ('smtp-out.{}', 25, 0), ('smtpout.{}', 25, 0),
    ('mail-out.{}', 25, 0), ('mailout.{}', 25, 0), ('smtp-in.{}', 25, 0),
    ('smtpin.{}', 25, 0), ('mail-in.{}', 25, 0), ('mailin.{}', 25, 0),
    ('smtp01.{}', 25, 0), ('smtp02.{}', 25, 0), ('mail01.{}', 25, 0),
    ('mail02.{}', 25, 0), ('smtp.secureserver.net.{}', 25, 0),
    ('smtp-gw.{}', 25, 0), ('smtpgw.{}', 25, 0), ('mail-gw.{}', 25, 0),
    ('mailgw.{}', 25, 0), ('smtp-gateway.{}', 25, 0), ('smtpgateway.{}', 25, 0),
    ('mail-gateway.{}', 25, 0), ('mailgateway.{}', 25, 0), ('smtp-server.{}', 25, 0),
    ('smtpserver.{}', 25, 0), ('mail-server.{}', 25, 0), ('mailserver.{}', 25, 0),
    ('smtpauth.{}', 587, 1), ('smtp-auth.{}', 587, 1), ('smtpauth.{}', 465, 1),
    ('secure-smtp.{}', 465, 1), ('securesmtp.{}', 465, 1), ('secure-mail.{}', 465, 1),
    ('securemail.{}', 465, 1), ('smtp-secure.{}', 465, 1), ('smtpsecure.{}', 465, 1),
    ('smtps.{}', 465, 1), ('smtp-ssl.{}', 465, 1), ('smtpssl.{}', 465, 1),
    ('mail-ssl.{}', 465, 1), ('mailssl.{}', 465, 1), ('webmail.{}', 443, 1),
    ('owa.{}', 443, 1), ('exchange.{}', 587, 1), ('exchange.{}', 25, 0),
    ('mailhost.{}', 25, 0), ('mail-host.{}', 25, 0), ('mailhub.{}', 25, 0),
    ('mail-hub.{}', 25, 0), ('smtprelay.{}', 587, 1), ('smtp-relay.{}', 587, 1),
    ('relay-mail.{}', 25, 0), ('relaymail.{}', 25, 0), ('relay-smtp.{}', 25, 0),
    ('relaysmtp.{}', 25, 0), ('mta.{}', 25, 0), ('mta1.{}', 25, 0),
    ('mta2.{}', 25, 0), ('sendmail.{}', 25, 0), ('postfix.{}', 25, 0),
    ('exim.{}', 25, 0), ('zimbra.{}', 25, 0), ('zimbra.{}', 587, 1),
    ('mx-relay.{}', 25, 0), ('mxrelay.{}', 25, 0), ('mx-gw.{}', 25, 0),
    ('mxgw.{}', 25, 0), ('gateway.{}', 25, 0), ('gw.{}', 25, 0),
    ('smtp-filter.{}', 25, 0), ('smtpfilter.{}', 25, 0), ('mail-filter.{}', 25, 0),
    ('mailfilter.{}', 25, 0), ('smtp-proxy.{}', 25, 0), ('smtpproxy.{}', 25, 0),
    ('mail-proxy.{}', 25, 0), ('mailproxy.{}', 25, 0), ('smtp-scan.{}', 25, 0),
    ('mail-scan.{}', 25, 0), ('mailscanner.{}', 25, 0), ('smtp-out1.{}', 25, 0),
    ('smtp-out2.{}', 25, 0), ('smtp-in1.{}', 25, 0), ('smtp-in2.{}', 25, 0),
    ('mail-out1.{}', 25, 0), ('mail-out2.{}', 25, 0), ('mail-in1.{}', 25, 0),
    ('mail-in2.{}', 25, 0), ('outbound.{}', 25, 0), ('outbound-mail.{}', 25, 0),
    ('inbound.{}', 25, 0), ('inbound-mail.{}', 25, 0), ('smtp-outbound.{}', 25, 0),
    ('smtp-inbound.{}', 25, 0), ('mail-outbound.{}', 25, 0), ('mail-inbound.{}', 25, 0),
    ('send.{}', 25, 0), ('send-mail.{}', 25, 0), ('smtp-send.{}', 25, 0),
    ('mail-send.{}', 25, 0), ('out.{}', 25, 0), ('out-mail.{}', 25, 0),
    ('out-smtp.{}', 25, 0), ('in-mail.{}', 25, 0), ('in-smtp.{}', 25, 0),
    ('out-mail.{}', 587, 1), ('out-smtp.{}', 587, 1), ('alt1.aspmx.l.google.{}', 25, 0),
    ('alt2.aspmx.l.google.{}', 25, 0), ('aspmx.l.google.{}', 25, 0),
    ('smtp.gmail.{}', 587, 1), ('smtp.office365.{}', 587, 1), ('smtp.live.{}', 587, 1),
    ('smtp.mail.yahoo.{}', 465, 1), ('smtp.mail.yahoo.{}', 587, 1),
    ('smtp.aol.{}', 465, 1), ('smtp.zoho.{}', 465, 1), ('smtp.zoho.{}', 587, 1),
    ('smtp.icloud.{}', 587, 1), ('smtp.mail.me.{}', 587, 1), ('exchange.{}', 465, 1),
    ('exchange-mail.{}', 25, 0), ('exchange-smtp.{}', 25, 0), ('exchange-relay.{}', 25, 0),
    ('exch.{}', 25, 0), ('exch1.{}', 25, 0), ('exch2.{}', 25, 0),
    ('smtp-mx.{}', 25, 0), ('smtpmx.{}', 25, 0), ('mail-mx.{}', 25, 0),
    ('mailmx.{}', 25, 0), ('mx-mail.{}', 25, 0), ('mxmail.{}', 25, 0),
    ('smtp-gw1.{}', 25, 0), ('smtp-gw2.{}', 25, 0), ('mail-gw1.{}', 25, 0),
    ('mail-gw2.{}', 25, 0), ('mx-gw1.{}', 25, 0), ('mx-gw2.{}', 25, 0),
    ('relay1.{}', 25, 0), ('relay2.{}', 25, 0), ('relay3.{}', 25, 0),
    ('relay01.{}', 25, 0), ('relay02.{}', 25, 0), ('relay-out.{}', 25, 0),
    ('relayout.{}', 25, 0), ('relay-in.{}', 25, 0), ('relayin.{}', 25, 0),
    ('smtp-relay1.{}', 25, 0), ('smtp-relay2.{}', 25, 0), ('mail-relay1.{}', 25, 0),
    ('mail-relay2.{}', 25, 0), ('backup-mail.{}', 25, 0), ('backup-smtp.{}', 25, 0),
    ('backup-mx.{}', 25, 0), ('backuprelay.{}', 25, 0), ('backup-relay.{}', 25, 0),
    ('secondary-mail.{}', 25, 0), ('secondary-mx.{}', 25, 0), ('secondary-smtp.{}', 25, 0),
    ('alt-mail.{}', 25, 0), ('alt-smtp.{}', 25, 0), ('alt-mx.{}', 25, 0),
    ('fallback-mail.{}', 25, 0), ('fallback-smtp.{}', 25, 0), ('fallback-mx.{}', 25, 0),
    ('failover-mail.{}', 25, 0), ('failover-smtp.{}', 25, 0), ('failover-mx.{}', 25, 0),
    ('smtp-alt.{}', 25, 0), ('smtp-alt.{}', 587, 1), ('smtpalt.{}', 25, 0),
    ('mail-alt.{}', 25, 0), ('mailalt.{}', 25, 0), ('mx-backup.{}', 25, 0),
    ('mxbackup.{}', 25, 0), ('smtp-eu.{}', 25, 0), ('smtp-us.{}', 25, 0),
    ('smtp-asia.{}', 25, 0), ('smtp-eu1.{}', 25, 0), ('smtp-eu2.{}', 25, 0),
    ('smtp-us1.{}', 25, 0), ('smtp-us2.{}', 25, 0), ('mail-eu.{}', 25, 0),
    ('mail-us.{}', 25, 0), ('mail-asia.{}', 25, 0), ('mx-eu.{}', 25, 0),
    ('mx-us.{}', 25, 0), ('mx-asia.{}', 25, 0), ('smtp-east.{}', 25, 0),
    ('smtp-west.{}', 25, 0), ('mail-east.{}', 25, 0), ('mail-west.{}', 25, 0),
    ('mx-east.{}', 25, 0), ('mx-west.{}', 25, 0), ('smtp-uk.{}', 25, 0),
    ('smtp-de.{}', 25, 0), ('smtp-fr.{}', 25, 0), ('smtp-jp.{}', 25, 0),
    ('smtp-au.{}', 25, 0), ('smtp-ca.{}', 25, 0), ('mail-uk.{}', 25, 0),
    ('mail-de.{}', 25, 0), ('mail-fr.{}', 25, 0), ('mail-jp.{}', 25, 0),
    ('mail-au.{}', 25, 0), ('barracuda.{}', 25, 0), ('mimecast.{}', 25, 0),
    ('proofpoint.{}', 25, 0), ('pphosted.{}', 25, 0), ('messagelabs.{}', 25, 0),
    ('spamfilter.{}', 25, 0), ('spam-filter.{}', 25, 0), ('antispam.{}', 25, 0),
    ('anti-spam.{}', 25, 0), ('emailsecurity.{}', 25, 0), ('email-security.{}', 25, 0),
    ('securitygateway.{}', 25, 0), ('security-gateway.{}', 25, 0), ('contentfilter.{}', 25, 0),
    ('content-filter.{}', 25, 0), ('ironport.{}', 25, 0), ('fortimail.{}', 25, 0),
    ('smtp-test.{}', 25, 0), ('smtp-dev.{}', 25, 0), ('smtp-staging.{}', 25, 0),
    ('smtp-prod.{}', 587, 1), ('mail-test.{}', 25, 0), ('mail-dev.{}', 25, 0),
    ('mail-staging.{}', 25, 0), ('mail-prod.{}', 25, 0), ('dev-mail.{}', 25, 0),
    ('dev-smtp.{}', 25, 0), ('test-mail.{}', 25, 0), ('test-smtp.{}', 25, 0),
    ('stage-mail.{}', 25, 0), ('stage-smtp.{}', 25, 0), ('prod-mail.{}', 25, 0),
    ('prod-smtp.{}', 587, 1), ('relay4.{}', 25, 0), ('relay5.{}', 25, 0),
    ('relay6.{}', 25, 0), ('relay7.{}', 25, 0), ('relay8.{}', 25, 0),
    ('relay9.{}', 25, 0), ('relay10.{}', 25, 0), ('smtp.sendgrid.{}', 587, 1),
    ('smtp.mailgun.{}', 587, 1), ('smtp.mandrill.{}', 587, 1), ('smtp.postmark.{}', 587, 1),
    ('smtp.sparkpost.{}', 587, 1), ('smtp.amazonses.{}', 587, 1), ('email-smtp.{}', 587, 1),
    ('ses.{}', 587, 1), ('sendgrid.{}', 25, 0), ('mailgun.{}', 25, 0),
    ('mailgun.{}', 587, 1), ('mandrill.{}', 587, 1), ('postmark.{}', 587, 1),
    ('sparkpost.{}', 587, 1), ('amazonses.{}', 587, 1), ('cpanel.{}', 25, 0),
    ('cpanel.{}', 465, 1), ('cpanel.{}', 587, 1), ('plesk.{}', 25, 0),
    ('plesk.{}', 587, 1), ('whm.{}', 25, 0), ('directadmin.{}', 25, 0),
    ('ispconfig.{}', 25, 0), ('smtp-tls.{}', 587, 1), ('smtptls.{}', 587, 1),
    ('mail-tls.{}', 587, 1), ('mailtls.{}', 587, 1), ('tls-smtp.{}', 587, 1),
    ('tlssmtp.{}', 587, 1), ('tls-mail.{}', 587, 1), ('tlsmail.{}', 587, 1),
    ('ssl-smtp.{}', 465, 1), ('sslsmtp.{}', 465, 1), ('ssl-mail.{}', 465, 1),
    ('sslmail.{}', 465, 1), ('starttls.{}', 587, 1), ('smtps-relay.{}', 465, 1),
    ('smtps-mail.{}', 465, 1), ('smtps-relay.{}', 587, 1), ('smtps-mail.{}', 587, 1),
    ('smtp-client.{}', 587, 1), ('smtpclient.{}', 587, 1), ('mail-client.{}', 25, 0),
    ('mailclient.{}', 25, 0), ('mailer.{}', 25, 0), ('mailer1.{}', 25, 0),
    ('mailer2.{}', 25, 0), ('post.{}', 25, 0), ('post-mail.{}', 25, 0),
    ('postmail.{}', 25, 0), ('post-smtp.{}', 25, 0), ('postsmtp.{}', 25, 0),
    ('postfix-mail.{}', 25, 0), ('postfix-smtp.{}', 25, 0), ('postbox.{}', 25, 0),
    ('mailbox.{}', 25, 0), ('mail-box.{}', 25, 0), ('inbox.{}', 25, 0),
    ('outbox.{}', 25, 0), ('postmaster.{}', 25, 0), ('mailer-daemon.{}', 25, 0),
    ('maildaemon.{}', 25, 0), ('smtp.corp.{}', 25, 0), ('mail.corp.{}', 25, 0),
    ('corp-mail.{}', 25, 0), ('corpmail.{}', 25, 0), ('corp-smtp.{}', 25, 0),
    ('corpsmtp.{}', 25, 0), ('smtp.internal.{}', 25, 0), ('mail.internal.{}', 25, 0),
    ('internal-mail.{}', 25, 0), ('internalmail.{}', 25, 0), ('internal-smtp.{}', 25, 0),
    ('internalsmtp.{}', 25, 0), ('smtp.local.{}', 25, 0), ('mail.local.{}', 25, 0),
    ('smtp.dmz.{}', 25, 0), ('mail.dmz.{}', 25, 0), ('dmz-mail.{}', 25, 0),
    ('dmz-smtp.{}', 25, 0), ('edge-mail.{}', 25, 0), ('edge-smtp.{}', 25, 0),
    ('edge-mx.{}', 25, 0), ('perimeter-mail.{}', 25, 0), ('perimeter-smtp.{}', 25, 0),
    ('border-mail.{}', 25, 0), ('border-smtp.{}', 25, 0), ('front-mail.{}', 25, 0),
    ('front-smtp.{}', 25, 0), ('frontend-mail.{}', 25, 0), ('frontend-smtp.{}', 25, 0),
    ('backend-mail.{}', 25, 0), ('backend-smtp.{}', 25, 0), ('smtp-aws.{}', 25, 0),
    ('smtp-azure.{}', 25, 0), ('smtp-gcp.{}', 25, 0), ('mail-aws.{}', 25, 0),
    ('mail-azure.{}', 25, 0), ('mail-gcp.{}', 25, 0), ('cloud-mail.{}', 25, 0),
    ('cloud-smtp.{}', 587, 1), ('cloud-email.{}', 25, 0), ('hosted-mail.{}', 25, 0),
    ('hosted-smtp.{}', 587, 1), ('managed-mail.{}', 25, 0), ('managed-smtp.{}', 587, 1),
    ('smtp-hosted.{}', 587, 1), ('mail-hosted.{}', 25, 0), ('mail-hosting.{}', 25, 0),
    ('smtp-hosting.{}', 25, 0), ('dc1-mail.{}', 25, 0), ('dc2-mail.{}', 25, 0),
    ('dc1-smtp.{}', 25, 0), ('dc2-smtp.{}', 25, 0), ('dc-mail.{}', 25, 0),
    ('dc-smtp.{}', 25, 0), ('datacenter-mail.{}', 25, 0), ('datacenter-smtp.{}', 25, 0),
    ('smtp-az1.{}', 25, 0), ('smtp-az2.{}', 25, 0), ('mail-az1.{}', 25, 0),
    ('mail-az2.{}', 25, 0), ('smtp-nyc.{}', 25, 0), ('smtp-lon.{}', 25, 0),
    ('smtp-tok.{}', 25, 0), ('smtp-par.{}', 25, 0), ('smtp-fra.{}', 25, 0),
    ('smtp-sfo.{}', 25, 0), ('smtp-ams.{}', 25, 0), ('mailservice.{}', 25, 0),
    ('mail-service.{}', 25, 0), ('mailsvc.{}', 25, 0), ('mail-svc.{}', 25, 0),
    ('mailapp.{}', 25, 0), ('mail-app.{}', 25, 0), ('mailagent.{}', 25, 0),
    ('mail-agent.{}', 25, 0), ('mailsrv.{}', 25, 0), ('mailsrv1.{}', 25, 0),
    ('mailsrv2.{}', 25, 0), ('smtpsrv.{}', 25, 0), ('smtpsrv1.{}', 25, 0),
    ('smtpsrv2.{}', 25, 0), ('emailserver.{}', 25, 0), ('emailserver.{}', 587, 1),
    ('email-server.{}', 25, 0), ('emailhost.{}', 25, 0), ('email-host.{}', 25, 0),
    ('auth-mail.{}', 25, 0), ('authmail.{}', 25, 0), ('auth-smtp.{}', 587, 1),
    ('authsmtp.{}', 587, 1), ('login-mail.{}', 25, 0), ('login-smtp.{}', 587, 1),
    ('authenticated-mail.{}', 25, 0), ('authenticated-smtp.{}', 587, 1), ('mail-api.{}', 25, 0),
    ('mailapi.{}', 25, 0), ('smtp-api.{}', 587, 1), ('smtpapi.{}', 587, 1),
    ('email-api.{}', 25, 0), ('emailapi.{}', 25, 0), ('api-mail.{}', 25, 0),
    ('apimail.{}', 25, 0), ('api-smtp.{}', 587, 1), ('apis.{}', 587, 1),
    ('api-email.{}', 587, 1), ('apiemail.{}', 587, 1), ('notification.{}', 587, 1),
    ('notifications.{}', 587, 1), ('notify.{}', 587, 1), ('alert.{}', 587, 1),
    ('alerts.{}', 587, 1), ('noreply.{}', 587, 1), ('no-reply.{}', 587, 1),
    ('donotreply.{}', 587, 1), ('system-mail.{}', 25, 0), ('systemmail.{}', 25, 0),
    ('system-smtp.{}', 587, 1), ('systemsmtp.{}', 587, 1), ('cron-mail.{}', 25, 0),
    ('cronmail.{}', 25, 0), ('auto-mail.{}', 25, 0), ('automail.{}', 25, 0),
    ('lb-mail.{}', 25, 0), ('lbmail.{}', 25, 0), ('lb-smtp.{}', 25, 0),
    ('lb1-mail.{}', 25, 0), ('lb2-mail.{}', 25, 0), ('cluster-mail.{}', 25, 0),
    ('clustermail.{}', 25, 0), ('cluster-smtp.{}', 25, 0), ('node-mail.{}', 25, 0),
    ('node1-mail.{}', 25, 0), ('node2-mail.{}', 25, 0), ('pool-mail.{}', 25, 0),
    ('pool-smtp.{}', 25, 0), ('shard-mail.{}', 25, 0), ('shard1-mail.{}', 25, 0),
    ('shard2-mail.{}', 25, 0), ('docker-mail.{}', 25, 0), ('docker-smtp.{}', 25, 0),
    ('k8s-mail.{}', 25, 0), ('k8s-smtp.{}', 25, 0), ('pod-mail.{}', 25, 0),
    ('pod-smtp.{}', 25, 0), ('container-mail.{}', 25, 0), ('container-smtp.{}', 25, 0),
    ('support-mail.{}', 25, 0), ('supportmail.{}', 25, 0), ('helpdesk-mail.{}', 25, 0),
    ('helpdeskmail.{}', 25, 0), ('sales-mail.{}', 25, 0), ('salesmail.{}', 25, 0),
    ('billing-mail.{}', 25, 0), ('billingmail.{}', 25, 0), ('crm-mail.{}', 25, 0),
    ('crmmail.{}', 25, 0), ('hr-mail.{}', 25, 0), ('hrmail.{}', 25, 0),
    ('info-mail.{}', 25, 0), ('infomail.{}', 25, 0), ('contact-mail.{}', 25, 0),
    ('contactmail.{}', 25, 0), ('invoice-mail.{}', 25, 0), ('invoicemail.{}', 25, 0),
    ('marketing-mail.{}', 25, 0), ('marketingsmtp.{}', 587, 1), ('marketing-smtp.{}', 587, 1),
    ('campaign-mail.{}', 25, 0), ('campaign-smtp.{}', 587, 1), ('bulk-mail.{}', 25, 0),
    ('bulkmail.{}', 25, 0), ('bulk-smtp.{}', 587, 1), ('bulksmtp.{}', 587, 1),
    ('mass-mail.{}', 25, 0), ('massmail.{}', 25, 0), ('newsletter.{}', 25, 0),
    ('newsletter-mail.{}', 25, 0), ('transactional.{}', 587, 1), ('transactional-mail.{}', 25, 0),
    ('transactional-smtp.{}', 587, 1), ('verify-mail.{}', 587, 1), ('verify-smtp.{}', 587, 1),
    ('verify.{}', 587, 1), ('confirm-mail.{}', 587, 1), ('confirm-smtp.{}', 587, 1),
    ('confirm.{}', 587, 1), ('activation-mail.{}', 587, 1), ('activation-smtp.{}', 587, 1),
    ('reset-mail.{}', 587, 1), ('reset-smtp.{}', 587, 1), ('password-mail.{}', 587, 1),
    ('password-smtp.{}', 587, 1), ('recover-mail.{}', 587, 1), ('recovery-smtp.{}', 587, 1),
    ('welcome-mail.{}', 587, 1), ('welcome-smtp.{}', 587, 1), ('correo.{}', 25, 0),
    ('correo.{}', 587, 1), ('correio.{}', 25, 0), ('poczta.{}', 25, 0),
    ('posta.{}', 25, 0), ('brief.{}', 25, 0), ('epost.{}', 25, 0),
    ('poste.{}', 25, 0), ('courriel.{}', 25, 0), ('smtp.mail.{}', 25, 0),
    ('smtp.mail.{}', 587, 1), ('mail.smtp.{}', 25, 0), ('mx.mail.{}', 25, 0),
    ('smtp.mx.{}', 25, 0), ('mail.mx.{}', 25, 0), ('smtp.relay.{}', 25, 0),
    ('mail.relay.{}', 25, 0), ('relay.mail.{}', 25, 0), ('relay.smtp.{}', 25, 0),
    ('mx.smtp.{}', 25, 0), ('mx.relay.{}', 25, 0), ('smtp.email.{}', 25, 0),
    ('smtp.email.{}', 587, 1), ('mail.email.{}', 25, 0), ('email.mail.{}', 25, 0),
    ('email.smtp.{}', 25, 0), ('smtp.post.{}', 25, 0), ('mail.post.{}', 25, 0),
    ('mx.email.{}', 25, 0), ('smtp1.mail.{}', 25, 0), ('smtp2.mail.{}', 25, 0),
    ('mx1.mail.{}', 25, 0), ('mx2.mail.{}', 25, 0), ('relay1.mail.{}', 25, 0),
    ('relay2.mail.{}', 25, 0), ('mail1.mail.{}', 25, 0), ('mail2.mail.{}', 25, 0),
    ('esmtp.{}', 25, 0), ('esmtp.{}', 587, 1), ('esmtp-relay.{}', 25, 0),
    ('smtpd.{}', 25, 0), ('smtpd.{}', 587, 1), ('qmail.{}', 25, 0),
    ('qmail-smtp.{}', 25, 0), ('exim-smtp.{}', 25, 0), ('exim4.{}', 25, 0),
    ('sendmail-server.{}', 25, 0), ('opensmtpd.{}', 25, 0), ('haraka.{}', 25, 0),
    ('dovecot.{}', 25, 0), ('dovecot-mail.{}', 25, 0), ('cyrus.{}', 25, 0),
    ('cyrus-mail.{}', 25, 0), ('maildrop.{}', 25, 0), ('mail-drop.{}', 25, 0),
    ('maildrop1.{}', 25, 0), ('maildrop2.{}', 25, 0), ('mailq.{}', 25, 0),
    ('mail-queue.{}', 25, 0), ('mailqueue.{}', 25, 0), ('queue-mail.{}', 25, 0),
    ('queuemail.{}', 25, 0), ('forward-mail.{}', 25, 0), ('forwardmail.{}', 25, 0),
    ('forwarder-mail.{}', 25, 0), ('forwardersmtp.{}', 25, 0), ('bounce-mail.{}', 25, 0),
    ('bouncemail.{}', 25, 0), ('bounce-smtp.{}', 587, 1), ('bouncesmtp.{}', 587, 1),
    ('redirect-mail.{}', 25, 0), ('redirectmail.{}', 25, 0), ('dr-mail.{}', 25, 0),
    ('dr-smtp.{}', 25, 0), ('dr-mx.{}', 25, 0), ('dr-relay.{}', 25, 0),
    ('disaster-mail.{}', 25, 0), ('disaster-smtp.{}', 25, 0), ('contingency-mail.{}', 25, 0),
    ('contingency-smtp.{}', 25, 0), ('standby-mail.{}', 25, 0), ('standby-smtp.{}', 25, 0),
    ('standby-mx.{}', 25, 0), ('mirror-mail.{}', 25, 0), ('mirror-smtp.{}', 25, 0),
    ('mirror-mx.{}', 25, 0), ('replica-mail.{}', 25, 0), ('replica-smtp.{}', 25, 0),
    ('replica-mx.{}', 25, 0), ('smtp-alt.{}', 2525, 0), ('mail-alt.{}', 2525, 0),
    ('smtp-alternate.{}', 2525, 0), ('mail-alternate.{}', 2525, 0), ('alt-smtp.{}', 2525, 0),
    ('alt-port.{}', 2525, 0), ('custom-mail.{}', 2525, 0), ('custom-smtp.{}', 2525, 0),
    ('smtp-custom.{}', 2525, 0), ('smtp-in1.{}', 587, 1), ('smtp-in2.{}', 587, 1),
    ('smtp-out1.{}', 587, 1), ('smtp-out2.{}', 587, 1), ('mx-in1.{}', 25, 0),
    ('mx-in2.{}', 25, 0), ('mx-out1.{}', 25, 0), ('mx-out2.{}', 25, 0),
    ('relay-in1.{}', 25, 0), ('relay-in2.{}', 25, 0), ('relay-out1.{}', 25, 0),
    ('relay-out2.{}', 25, 0), ('mx-relay-in.{}', 25, 0), ('mx-relay-out.{}', 25, 0),
    ('smtp-mx-in.{}', 25, 0), ('smtp-mx-out.{}', 25, 0), ('mail-mx-in.{}', 25, 0),
    ('mail-mx-out.{}', 25, 0), ('in-mail-relay.{}', 25, 0), ('out-mail-relay.{}', 25, 0),
    ('in-smtp-relay.{}', 25, 0), ('out-smtp-relay.{}', 25, 0), ('saas-mail.{}', 25, 0),
    ('saas-smtp.{}', 587, 1), ('cloud-mail.{}', 587, 1), ('cloud-smtp.{}', 25, 0),
    ('cloud-email.{}', 587, 1), ('cloud-mx.{}', 25, 0), ('cloud-relay.{}', 25, 0),
    ('vps-mail.{}', 25, 0), ('vps-smtp.{}', 587, 1), ('dedicated-mail.{}', 25, 0),
    ('dedicated-smtp.{}', 587, 1), ('shared-mail.{}', 25, 0), ('shared-smtp.{}', 587, 1),
    ('reseller-mail.{}', 25, 0), ('reseller-smtp.{}', 587, 1), ('mail-edge.{}', 25, 0),
    ('smtp-edge.{}', 25, 0), ('mx-edge.{}', 25, 0), ('relay-edge.{}', 25, 0),
    ('edge-mail-1.{}', 25, 0), ('edge-mail-2.{}', 25, 0), ('edge-smtp-1.{}', 25, 0),
    ('edge-smtp-2.{}', 25, 0), ('edge-mx-1.{}', 25, 0), ('edge-mx-2.{}', 25, 0),
    ('cdn-mail.{}', 25, 0), ('cdn-smtp.{}', 25, 0), ('cdn-mx.{}', 25, 0),
    ('cdn-relay.{}', 25, 0), ('pop-mail.{}', 25, 0), ('pop-smtp.{}', 25, 0),
    ('proxy-mail.{}', 25, 0), ('proxy-smtp.{}', 25, 0), ('proxy-mx.{}', 25, 0),
    ('proxy-relay.{}', 25, 0), ('forward-mail-1.{}', 25, 0), ('forward-mail-2.{}', 25, 0),
    ('forwarder-smtp.{}', 25, 0), ('redirect-smtp.{}', 25, 0), ('mail-smtp-relay-gw.{}', 25, 0),
    ('smtp-mail-relay-gw.{}', 25, 0), ('relay-mail-smtp-gw.{}', 25, 0), ('gw-mail-smtp-relay.{}', 25, 0),
    ('gw-smtp-mail-relay.{}', 25, 0), ('relay-gw-mail-smtp.{}', 25, 0), ('mail-out-relay-smtp.{}', 25, 0),
    ('smtp-out-relay-mail.{}', 25, 0), ('relay-out-mail-smtp.{}', 25, 0), ('smtp-in-relay-mail.{}', 25, 0),
    ('mail-in-relay-smtp.{}', 25, 0), ('relay-in-mail-smtp.{}', 25, 0), ('primary-mail-relay.{}', 25, 0),
    ('primary-smtp-relay.{}', 25, 0), ('secondary-mail-relay.{}', 25, 0), ('secondary-smtp-relay.{}', 25, 0),
    ('backup-mail-relay-gw.{}', 25, 0), ('backup-smtp-relay-gw.{}', 25, 0), ('smtp-tls.{}', 25, 0),
    ('mail-tls.{}', 25, 0), ('tls-relay.{}', 587, 1), ('tls-relay.{}', 25, 0),
    ('ssl-relay.{}', 465, 1), ('ssl-relay.{}', 25, 0), ('tls-mx.{}', 587, 1),
    ('ssl-mx.{}', 465, 1), ('smtp3a.{}', 25, 0), ('smtp3b.{}', 25, 0),
    ('mail3a.{}', 25, 0), ('mail3b.{}', 25, 0), ('relay1a.{}', 25, 0),
    ('relay1b.{}', 25, 0), ('relay2a.{}', 25, 0), ('relay2b.{}', 25, 0),
    ('mx3a.{}', 25, 0), ('mx3b.{}', 25, 0), ('esmtp1.{}', 25, 0),
    ('esmtp2.{}', 25, 0), ('esmtp-relay.{}', 587, 1), ('smtps1.{}', 465, 1),
    ('smtps2.{}', 465, 1), ('smtps1.{}', 587, 1), ('smtps2.{}', 587, 1),
    ('simple-mail.{}', 25, 0), ('simple-mail.{}', 587, 1), ('simplemail.{}', 25, 0),
    ('simplemail.{}', 587, 1), ('simple-smtp.{}', 25, 0), ('simple-smtp.{}', 587, 1),
    ('simplesmtp.{}', 25, 0), ('simplesmtp.{}', 587, 1), ('simple-mx.{}', 25, 0),
    ('simplemx.{}', 25, 0), ('m-smtp.{}', 25, 0), ('m-mail.{}', 25, 0),
    ('e-smtp.{}', 25, 0), ('e-mail-server.{}', 25, 0), ('mail-s.{}', 25, 0),
    ('mail-m.{}', 25, 0), ('mail-e.{}', 25, 0), ('smtp-s.{}', 25, 0),
    ('smtp-m.{}', 25, 0), ('smtp-e.{}', 25, 0), ('mx-s.{}', 25, 0),
    ('mx-m.{}', 25, 0), ('mx-e.{}', 25, 0), ('smtp-mail-out.{}', 587, 1),
    ('smtp-mail-out.{}', 25, 0), ('smtp-mail-in.{}', 25, 0), ('mail-smtp-out.{}', 587, 1),
    ('mail-smtp-out.{}', 25, 0), ('mail-smtp-in.{}', 25, 0), ('out-mail-smtp-relay.{}', 587, 1),
    ('out-mail-smtp-relay.{}', 25, 0), ('in-mail-smtp-relay.{}', 25, 0), ('mail-relay-out.{}', 587, 1),
    ('smtp-relay-out.{}', 587, 1), ('relay-mail-out.{}', 587, 1), ('relay-mail-in.{}', 25, 0),
    ('mail-hosted-1.{}', 25, 0), ('mail-hosted-2.{}', 25, 0), ('smtp-hosted-1.{}', 587, 1),
    ('smtp-hosted-2.{}', 587, 1), ('secure-mail-relay.{}', 465, 1), ('secure-smtp-relay.{}', 465, 1),
    ('secure-mx-relay.{}', 465, 1), ('secure-email-relay.{}', 465, 1), ('secure-relay-mail.{}', 465, 1),
    ('secure-relay-smtp.{}', 465, 1), ('secure-relay-mx.{}', 465, 1), ('secure-relay-email.{}', 465, 1),
    ('secure1-mail.{}', 465, 1), ('secure2-mail.{}', 465, 1), ('secure1-smtp.{}', 465, 1),
    ('secure2-smtp.{}', 465, 1), ('secure1-mx.{}', 465, 1), ('secure2-mx.{}', 465, 1),
    ('smtp-mail-mx-relay.{}', 25, 0), ('mail-smtp-mx-relay.{}', 25, 0), ('mx-mail-smtp-relay.{}', 25, 0),
    ('relay-mx-mail-smtp.{}', 25, 0), ('smtp-relay-mail-mx.{}', 25, 0), ('mail-relay-smtp-mx.{}', 25, 0),
    ('mx-relay-smtp-mail.{}', 25, 0), ('relay-mx-smtp-mail.{}', 25, 0), ('smtp-br.{}', 25, 0),
    ('smtp-es.{}', 25, 0), ('smtp-it.{}', 25, 0), ('smtp-ru.{}', 25, 0),
    ('smtp-nl.{}', 25, 0), ('smtp-se.{}', 25, 0), ('smtp-no.{}', 25, 0),
    ('smtp-fi.{}', 25, 0), ('smtp-dk.{}', 25, 0), ('smtp-pl.{}', 25, 0),
    ('smtp-at.{}', 25, 0), ('smtp-ch.{}', 25, 0), ('smtp-be.{}', 25, 0),
    ('smtp-pt.{}', 25, 0), ('smtp-gr.{}', 25, 0), ('smtp-tr.{}', 25, 0),
    ('smtp-kr.{}', 25, 0), ('smtp-tw.{}', 25, 0), ('smtp-hk.{}', 25, 0),
    ('smtp-sg.{}', 25, 0), ('smtp-my.{}', 25, 0), ('smtp-th.{}', 25, 0),
    ('smtp-vn.{}', 25, 0), ('smtp-id.{}', 25, 0), ('smtp-ph.{}', 25, 0),
    ('smtp-nz.{}', 25, 0), ('smtp-za.{}', 25, 0), ('smtp-ae.{}', 25, 0),
    ('smtp-sa.{}', 25, 0), ('smtp-il.{}', 25, 0), ('smtp-ar.{}', 25, 0),
    ('smtp-cl.{}', 25, 0), ('smtp-co.{}', 25, 0), ('smtp-pe.{}', 25, 0),
    ('mx-gateway-1.{}', 25, 0), ('mx-gateway-2.{}', 25, 0), ('relay-gateway-1.{}', 25, 0),
    ('relay-gateway-2.{}', 25, 0), ('email-gateway-1.{}', 25, 0), ('email-gateway-2.{}', 25, 0),
    ('emailgw1.{}', 25, 0), ('emailgw2.{}', 25, 0), ('smtp465.{}', 465, 1),
    ('smtp587.{}', 587, 1), ('mail25.{}', 25, 0), ('mail465.{}', 465, 1),
    ('mail587.{}', 587, 1), ('mx25.{}', 25, 0), ('mx465.{}', 465, 1),
    ('mx587.{}', 587, 1), ('fast-mail.{}', 25, 0), ('fastmail.{}', 25, 0),
    ('fast-smtp.{}', 587, 1), ('fastsmtp.{}', 587, 1), ('quick-mail.{}', 25, 0),
    ('quickmail.{}', 25, 0), ('quick-smtp.{}', 587, 1), ('quicksmtp.{}', 587, 1),
    ('rapid-mail.{}', 25, 0), ('rapidmail.{}', 25, 0), ('rapid-smtp.{}', 587, 1),
    ('rapidsmtp.{}', 587, 1), ('speed-mail.{}', 25, 0), ('speedmail.{}', 25, 0),
    ('speed-smtp.{}', 587, 1), ('speedsmtp.{}', 587, 1), ('turbo-mail.{}', 25, 0),
    ('turbomail.{}', 25, 0), ('turbo-smtp.{}', 587, 1), ('turbosmtp.{}', 587, 1),
    ('relayserver.{}', 25, 0), ('mxserver.{}', 25, 0), ('smtp03.{}', 25, 0),
    ('smtp04.{}', 25, 0), ('smtp.secureserver.{}', 25, 0), ('smtpout.{}', 465, 1),
    ('smtp2go.{}', 25, 0), ('smtpin.{}', 465, 1), ('smtps.{}', 587, 1),
    ('smtpclient.{}', 25, 0), ('smtpsend.{}', 25, 0), ('smtp.mailserver.{}', 25, 0),
    ('smtp.msg.{}', 25, 0), ('smtp.mess.{}', 25, 0), ('smtp.test.{}', 25, 0),
    ('smtp.dev.{}', 25, 0), ('smtp.staging.{}', 25, 0), ('smtp.prod.{}', 25, 0),
    ('smtp.office.{}', 587, 1), ('smtp.biz.{}', 587, 1), ('smtp.cloud.{}', 587, 1),
    ('smtp.web.{}', 25, 0), ('smtp.host.{}', 25, 0), ('smtp.server.{}', 25, 0),
    ('smtp.net.{}', 25, 0), ('smtp.link.{}', 25, 0), ('smtp.systems.{}', 25, 0),
    ('smtp.services.{}', 25, 0), ('smtp.solutions.{}', 25, 0), ('smtp.tech.{}', 587, 1),
    ('smtp.io.{}', 587, 1), ('mail03.{}', 25, 0), ('mail04.{}', 25, 0),
    ('mail05.{}', 25, 0), ('mail-in.{}', 465, 1), ('mailout.{}', 587, 1),
    ('mail-gate.{}', 25, 0), ('mailgate.{}', 25, 0), ('mailscan.{}', 25, 0),
    ('mail-scanner.{}', 25, 0), ('mailserv.{}', 25, 0), ('mail-serv.{}', 25, 0),
    ('mailsend.{}', 25, 0), ('mailrecv.{}', 25, 0), ('mail-recv.{}', 25, 0),
    ('mailsecure.{}', 465, 1), ('mail-secure.{}', 465, 1), ('mailauth.{}', 587, 1),
    ('mail-auth.{}', 587, 1), ('mail.msg.{}', 25, 0), ('mail.web.{}', 25, 0),
    ('mail.cloud.{}', 587, 1), ('mail.office.{}', 587, 1), ('mail.biz.{}', 587, 1),
    ('mail.host.{}', 25, 0), ('mail.net.{}', 25, 0), ('mail.io.{}', 587, 1),
    ('mail.link.{}', 25, 0), ('mx-in.{}', 25, 0), ('mxin.{}', 25, 0),
    ('mx-out.{}', 25, 0), ('mxout.{}', 25, 0), ('mx-gateway.{}', 25, 0),
    ('mxgateway.{}', 25, 0), ('mx-proxy.{}', 25, 0), ('mxproxy.{}', 25, 0),
    ('mx-filter.{}', 25, 0), ('mxfilter.{}', 25, 0), ('mx-server.{}', 25, 0),
    ('mx-host.{}', 25, 0), ('mxhost.{}', 25, 0), ('mx-secure.{}', 465, 1),
    ('mxsecure.{}', 465, 1), ('mx-ssl.{}', 465, 1), ('mxssl.{}', 465, 1),
    ('mxauth.{}', 587, 1), ('mx-auth.{}', 587, 1), ('mx-in.{}', 465, 1),
    ('mx-out.{}', 587, 1), ('mx.cloud.{}', 587, 1), ('mx.corp.{}', 25, 0),
    ('mx.internal.{}', 25, 0), ('mx.io.{}', 587, 1), ('relay03.{}', 25, 0),
    ('relay-mx.{}', 25, 0), ('relaymx.{}', 25, 0), ('relay-gw.{}', 25, 0),
    ('relaygw.{}', 25, 0), ('relay-secure.{}', 465, 1), ('relaysecure.{}', 465, 1),
    ('relay-ssl.{}', 465, 1), ('relayssl.{}', 465, 1), ('relay-auth.{}', 587, 1),
    ('relayauth.{}', 587, 1), ('relay.internal.{}', 25, 0), ('relay.corp.{}', 25, 0),
    ('relay.dmz.{}', 25, 0), ('relay.email.{}', 25, 0), ('relay.host.{}', 25, 0),
    ('relay.net.{}', 25, 0), ('exchange1.{}', 25, 0), ('exchange2.{}', 25, 0),
    ('exchange01.{}', 25, 0), ('exchange02.{}', 25, 0), ('exchangemail.{}', 25, 0),
    ('exchangesmtp.{}', 25, 0), ('exchangerelay.{}', 25, 0), ('exchange-mx.{}', 25, 0),
    ('exchangemx.{}', 25, 0), ('exchange-secure.{}', 465, 1), ('exchange-ssl.{}', 465, 1),
    ('exchange-auth.{}', 587, 1), ('exchange.internal.{}', 25, 0), ('exchange.corp.{}', 25, 0),
    ('exchange.mail.{}', 25, 0), ('exch01.{}', 25, 0), ('exch02.{}', 25, 0),
    ('post1.{}', 25, 0), ('post2.{}', 25, 0), ('post-relay.{}', 25, 0),
    ('postrelay.{}', 25, 0), ('post-box.{}', 25, 0), ('postfix1.{}', 25, 0),
    ('postfix2.{}', 25, 0), ('gw1.{}', 25, 0), ('gw2.{}', 25, 0),
    ('gw01.{}', 25, 0), ('gw02.{}', 25, 0), ('gw-mail.{}', 25, 0),
    ('gwmail.{}', 25, 0), ('gw-smtp.{}', 25, 0), ('gwsmtp.{}', 25, 0),
    ('gw-relay.{}', 25, 0), ('gwrelay.{}', 25, 0), ('send1.{}', 25, 0),
    ('send2.{}', 25, 0), ('send01.{}', 25, 0), ('send02.{}', 25, 0),
    ('sendout.{}', 25, 0), ('send-out.{}', 25, 0), ('sender.{}', 25, 0),
    ('sending.{}', 25, 0), ('smtp-send.{}', 587, 1), ('mail-send.{}', 587, 1),
    ('out1.{}', 25, 0), ('out2.{}', 25, 0), ('outbound1.{}', 25, 0),
    ('outbound2.{}', 25, 0), ('outmail.{}', 25, 0), ('outsmtp.{}', 25, 0),
    ('out-relay.{}', 25, 0), ('outrelay.{}', 25, 0), ('outboundmail.{}', 25, 0),
    ('outbound-relay.{}', 25, 0), ('outboundrelay.{}', 25, 0), ('outbound-smtp.{}', 587, 1),
    ('outbound-smtp.{}', 25, 0), ('in.{}', 25, 0), ('in1.{}', 25, 0),
    ('in2.{}', 25, 0), ('inbound1.{}', 25, 0), ('inbound2.{}', 25, 0),
    ('inmail.{}', 25, 0), ('insmtp.{}', 25, 0), ('in-relay.{}', 25, 0),
    ('inrelay.{}', 25, 0), ('inboundmail.{}', 25, 0), ('inbound-relay.{}', 25, 0),
    ('inboundrelay.{}', 25, 0), ('pops.{}', 995, 1), ('pop3s.{}', 995, 1),
    ('pop-mail.{}', 110, 0), ('popmail.{}', 110, 0), ('imaps.{}', 993, 1),
    ('imap-mail.{}', 143, 0), ('imapmail.{}', 143, 0), ('imap4.{}', 143, 0),
    ('imap4.{}', 993, 1), ('webmail.{}', 25, 0), ('webmail1.{}', 443, 1),
    ('webmail2.{}', 443, 1), ('owa.{}', 25, 0), ('googlemail.{}', 25, 0),
    ('gmail.{}', 25, 0), ('aspmx.{}', 25, 0), ('aspmx1.{}', 25, 0),
    ('aspmx2.{}', 25, 0), ('aspmx3.{}', 25, 0), ('outlook.{}', 25, 0),
    ('outlook.{}', 587, 1), ('office365.{}', 587, 1), ('microsoft.{}', 25, 0),
    ('zoho.{}', 25, 0), ('yahoo.{}', 25, 0), ('hotmail.{}', 25, 0),
    ('icloud.{}', 25, 0), ('proton.{}', 25, 0), ('protonmail.{}', 25, 0),
    ('yandex.{}', 25, 0), ('mandrill.{}', 25, 0), ('mailchimp.{}', 25, 0),
    ('amazonses.{}', 25, 0), ('postmark.{}', 25, 0), ('sparkpost.{}', 25, 0),
    ('barracuda.{}', 587, 1), ('mimecast.{}', 587, 1), ('symantec.{}', 25, 0),
    ('trendmicro.{}', 25, 0), ('mcafee.{}', 25, 0), ('antivirus.{}', 25, 0),
    ('anti-virus.{}', 25, 0), ('virusfilter.{}', 25, 0), ('virus-filter.{}', 25, 0),
    ('messagefilter.{}', 25, 0), ('message-filter.{}', 25, 0), ('mta3.{}', 25, 0),
    ('mta01.{}', 25, 0), ('mta02.{}', 25, 0), ('mta03.{}', 25, 0),
    ('mta-1.{}', 25, 0), ('mta-2.{}', 25, 0), ('mta-3.{}', 25, 0),
    ('msg.{}', 25, 0), ('messaging.{}', 25, 0), ('message.{}', 25, 0),
    ('messages.{}', 25, 0), ('msg-server.{}', 25, 0), ('msgserver.{}', 25, 0),
    ('msg-gw.{}', 25, 0), ('msggw.{}', 25, 0), ('message-gateway.{}', 25, 0),
    ('messagegateway.{}', 25, 0), ('messaging-server.{}', 25, 0), ('messagingserver.{}', 25, 0),
    ('smtp-cn.{}', 25, 0), ('smtp-north.{}', 25, 0), ('smtp-south.{}', 25, 0),
    ('smtp-central.{}', 25, 0), ('smtp05.{}', 25, 0), ('smtp06.{}', 25, 0),
    ('smtp07.{}', 25, 0), ('smtp08.{}', 25, 0), ('smtp09.{}', 25, 0),
    ('smtp10.{}', 587, 1), ('mail06.{}', 25, 0), ('mail07.{}', 25, 0),
    ('mail08.{}', 25, 0), ('mail09.{}', 25, 0), ('mail10.{}', 587, 1),
    ('mx10.{}', 587, 1), ('email1.{}', 25, 0), ('email2.{}', 25, 0),
    ('email01.{}', 25, 0), ('email02.{}', 25, 0), ('e-mail.{}', 25, 0),
    ('e-mail.{}', 587, 1), ('emailer.{}', 25, 0), ('emailer1.{}', 25, 0),
    ('emailer2.{}', 25, 0), ('email-relay.{}', 25, 0), ('emailrelay.{}', 25, 0),
    ('emailsmtp.{}', 587, 1), ('email-gw.{}', 25, 0), ('emailgw.{}', 25, 0),
    ('email-mx.{}', 25, 0), ('emailmx.{}', 25, 0), ('email-secure.{}', 465, 1),
    ('emailsecure.{}', 465, 1), ('email-ssl.{}', 465, 1), ('emailssl.{}', 465, 1),
    ('email-auth.{}', 587, 1), ('emailauth.{}', 587, 1), ('email-filter.{}', 25, 0),
    ('emailfilter.{}', 25, 0), ('email-scan.{}', 25, 0), ('emailscan.{}', 25, 0),
    ('email-cloud.{}', 587, 1), ('emailcloud.{}', 587, 1), ('email-mail.{}', 25, 0),
    ('postal.{}', 25, 0), ('postman.{}', 25, 0), ('courier.{}', 25, 0),
    ('bulk.{}', 25, 0), ('news.{}', 25, 0), ('nntp.{}', 119, 0),
    ('newsgroup.{}', 119, 0), ('usenet.{}', 119, 0), ('list.{}', 25, 0),
    ('lists.{}', 25, 0), ('mailinglist.{}', 25, 0), ('mailing-list.{}', 25, 0),
    ('mailman.{}', 25, 0), ('mailqueue1.{}', 25, 0), ('mailqueue2.{}', 25, 0),
    ('queue.{}', 25, 0), ('mbox.{}', 25, 0), ('maildir.{}', 25, 0),
    ('box.{}', 25, 0), ('in-box.{}', 25, 0), ('out-box.{}', 25, 0),
    ('forward.{}', 25, 0), ('forwarder.{}', 25, 0), ('redirect.{}', 25, 0),
    ('bounce.{}', 25, 0), ('bouncer.{}', 25, 0), ('internal-relay.{}', 25, 0),
    ('internalrelay.{}', 25, 0), ('corp-relay.{}', 25, 0), ('corprelay.{}', 25, 0),
    ('corp-mx.{}', 25, 0), ('corpmx.{}', 25, 0), ('local-mail.{}', 25, 0),
    ('localmail.{}', 25, 0), ('local-smtp.{}', 25, 0), ('localsmtp.{}', 25, 0),
    ('local-relay.{}', 25, 0), ('localrelay.{}', 25, 0), ('dmzmail.{}', 25, 0),
    ('dmzsmtp.{}', 25, 0), ('dmz-relay.{}', 25, 0), ('dmzrelay.{}', 25, 0),
    ('ns.{}', 25, 0), ('ns1.{}', 25, 0), ('ns2.{}', 25, 0),
    ('www-mail.{}', 25, 0), ('wwwmail.{}', 25, 0), ('web-mail.{}', 25, 0),
    ('web-smtp.{}', 587, 1), ('webrtc-mail.{}', 25, 0), ('apis.{}', 25, 0),
    ('virtualmin.{}', 25, 0), ('webmin.{}', 25, 0), ('postfixadmin.{}', 25, 0),
    ('exim-mail.{}', 25, 0), ('msexchange.{}', 25, 0), ('ms-exchange.{}', 25, 0),
    ('lotus.{}', 25, 0), ('lotusnotes.{}', 25, 0), ('lotus-notes.{}', 25, 0),
    ('domino.{}', 25, 0), ('notes.{}', 25, 0), ('groupwise.{}', 25, 0),
    ('kerio.{}', 25, 0), ('exim4.{}', 587, 1), ('smtp.out.{}', 587, 1),
    ('mail.out.{}', 25, 0), ('out.mail.{}', 25, 0), ('smtp.relay.{}', 587, 1),
    ('smtp.mx.{}', 587, 1), ('smtp.gw.{}', 25, 0), ('mail.gw.{}', 25, 0),
    ('gw.mail.{}', 25, 0), ('smtp.gw.{}', 587, 1), ('smtp1.smtp.{}', 25, 0),
    ('smtp2.smtp.{}', 25, 0), ('relay1.relay.{}', 25, 0), ('relay2.relay.{}', 25, 0),
    ('mx1.mx.{}', 25, 0), ('mx2.mx.{}', 25, 0), ('secure.{}', 465, 1),
    ('secure.{}', 587, 1), ('secure1.{}', 465, 1), ('secure2.{}', 465, 1),
    ('secure-mail.{}', 587, 1), ('encrypt-mail.{}', 465, 1), ('encryptmail.{}', 465, 1),
    ('encrypted.{}', 465, 1), ('crypto-mail.{}', 465, 1), ('start-tls.{}', 587, 1),
    ('starttls-mail.{}', 587, 1), ('smtp-mail-relay.{}', 25, 0), ('mail-smtp-relay.{}', 25, 0),
    ('relay-mail-smtp.{}', 25, 0), ('smtp-relay-mail.{}', 25, 0), ('mail-relay-smtp.{}', 25, 0),
    ('smtp-mx-relay.{}', 25, 0), ('mx-smtp-relay.{}', 25, 0), ('smtp-out-mail.{}', 587, 1),
    ('out-mail-smtp.{}', 587, 1), ('mail-out-smtp.{}', 587, 1), ('smtp-in-mail.{}', 25, 0),
    ('in-mail-smtp.{}', 25, 0), ('mail-in-smtp.{}', 25, 0), ('email-smtp-relay.{}', 25, 0),
    ('smtp-email-relay.{}', 25, 0), ('relay-email-smtp.{}', 25, 0), ('smtp-1.{}', 25, 0),
    ('smtp-2.{}', 25, 0), ('smtp-3.{}', 25, 0), ('smtp-4.{}', 25, 0),
    ('smtp-5.{}', 25, 0), ('smtp-01.{}', 25, 0), ('smtp-02.{}', 25, 0),
    ('smtp-03.{}', 25, 0), ('smtp-04.{}', 25, 0), ('smtp-05.{}', 25, 0),
    ('mail-1.{}', 25, 0), ('mail-2.{}', 25, 0), ('mail-3.{}', 25, 0),
    ('mail-4.{}', 25, 0), ('mail-5.{}', 25, 0), ('mail-01.{}', 25, 0),
    ('mail-02.{}', 25, 0), ('mail-03.{}', 25, 0), ('mail-04.{}', 25, 0),
    ('mail-05.{}', 25, 0), ('mx-1.{}', 25, 0), ('mx-2.{}', 25, 0),
    ('mx-3.{}', 25, 0), ('mx-4.{}', 25, 0), ('mx-5.{}', 25, 0),
    ('mx-01.{}', 25, 0), ('mx-02.{}', 25, 0), ('mx-03.{}', 25, 0),
    ('mx-04.{}', 25, 0), ('mx-05.{}', 25, 0), ('relay-1.{}', 25, 0),
    ('relay-2.{}', 25, 0), ('relay-3.{}', 25, 0), ('relay-01.{}', 25, 0),
    ('relay-02.{}', 25, 0), ('relay-03.{}', 25, 0), ('postmail.{}', 587, 1),
    ('mailpost.{}', 25, 0), ('mail-post.{}', 25, 0), ('mail-daemon.{}', 25, 0),
    ('mailerdaemon.{}', 25, 0), ('postmaster-mail.{}', 25, 0), ('webmaster-mail.{}', 25, 0),
    ('admin-mail.{}', 25, 0), ('adminmail.{}', 25, 0), ('admin-smtp.{}', 587, 1),
    ('adminsmtp.{}', 587, 1), ('m.{}', 25, 0), ('m1.{}', 25, 0),
    ('m2.{}', 25, 0), ('m01.{}', 25, 0), ('m02.{}', 25, 0),
    ('e.{}', 25, 0), ('e1.{}', 25, 0), ('e2.{}', 25, 0),
    ('e01.{}', 25, 0), ('e02.{}', 25, 0), ('s.{}', 25, 0),
    ('s1.{}', 25, 0), ('s2.{}', 25, 0), ('s01.{}', 25, 0),
    ('s02.{}', 25, 0), ('mx0.{}', 25, 0), ('mail0.{}', 25, 0),
    ('smtp0.{}', 25, 0), ('relay0.{}', 25, 0), ('email0.{}', 25, 0),
    ('smtp-d.{}', 25, 0), ('mail-d.{}', 25, 0), ('mx-d.{}', 25, 0),
    ('relay-c.{}', 25, 0), ('relay-d.{}', 25, 0), ('messaging.{}', 587, 1),
    ('alert-mail.{}', 587, 1), ('alertmail.{}', 587, 1), ('automation-mail.{}', 587, 1),
    ('batch-mail.{}', 25, 0), ('batchmail.{}', 25, 0), ('erp-mail.{}', 25, 0),
    ('erpmail.{}', 25, 0), ('accounting-mail.{}', 25, 0), ('accountingmail.{}', 25, 0),
    ('backupmail.{}', 25, 0), ('backupsmtp.{}', 25, 0), ('backupmx.{}', 25, 0),
    ('fallbackmail.{}', 25, 0), ('fallbacksmtp.{}', 25, 0), ('fallbackmx.{}', 25, 0),
    ('failovermail.{}', 25, 0), ('failoversmtp.{}', 25, 0), ('failovermx.{}', 25, 0),
    ('standbymail.{}', 25, 0), ('standbysmtp.{}', 25, 0), ('standbymx.{}', 25, 0),
    ('mirrormail.{}', 25, 0), ('mirrorsmtp.{}', 25, 0), ('mirrormx.{}', 25, 0),
    ('replicamail.{}', 25, 0), ('replicasmtp.{}', 25, 0), ('replicamx.{}', 25, 0),
    ('devmail.{}', 25, 0), ('devsmtp.{}', 25, 0), ('dev-mx.{}', 25, 0),
    ('devmx.{}', 25, 0), ('staging-mail.{}', 25, 0), ('stagingmail.{}', 25, 0),
    ('staging-smtp.{}', 25, 0), ('stagingsmtp.{}', 25, 0), ('staging-mx.{}', 25, 0),
    ('stagingmx.{}', 25, 0), ('prodmail.{}', 25, 0), ('prodsmtp.{}', 587, 1),
    ('prod-mx.{}', 25, 0), ('prodmx.{}', 25, 0), ('qa-mail.{}', 25, 0),
    ('qamail.{}', 25, 0), ('qa-smtp.{}', 25, 0), ('qasmtp.{}', 25, 0),
    ('testmail.{}', 25, 0), ('testsmtp.{}', 25, 0), ('test-mx.{}', 25, 0),
    ('testmx.{}', 25, 0), ('demo-mail.{}', 25, 0), ('demomail.{}', 25, 0),
    ('demo-smtp.{}', 25, 0), ('demosmtp.{}', 25, 0), ('sandbox-mail.{}', 25, 0),
    ('sandboxmail.{}', 25, 0), ('sandbox-smtp.{}', 25, 0), ('sandboxsmtp.{}', 25, 0),
    ('sandbox-mx.{}', 25, 0), ('sandboxmx.{}', 25, 0), ('smtp-alpha.{}', 25, 0),
    ('smtp-beta.{}', 25, 0), ('smtp-gamma.{}', 25, 0), ('mail-alpha.{}', 25, 0),
    ('mail-beta.{}', 25, 0), ('mx-alpha.{}', 25, 0), ('mx-beta.{}', 25, 0),
    ('relay-alpha.{}', 25, 0), ('relay-beta.{}', 25, 0), ('smtp-oci.{}', 25, 0),
    ('smtp-do.{}', 25, 0), ('mx-aws.{}', 25, 0), ('mx-azure.{}', 25, 0),
    ('mx-gcp.{}', 25, 0), ('relay-aws.{}', 25, 0), ('relay-azure.{}', 25, 0),
    ('relay-gcp.{}', 25, 0), ('e1.mail.{}', 25, 0), ('e2.mail.{}', 25, 0),
    ('m1.mail.{}', 25, 0), ('m2.mail.{}', 25, 0), ('n1.mail.{}', 25, 0),
    ('n2.mail.{}', 25, 0), ('p1.mail.{}', 25, 0), ('p2.mail.{}', 25, 0),
    ('r1.mail.{}', 25, 0), ('r2.mail.{}', 25, 0), ('postino.{}', 25, 0),
    ('postino1.{}', 25, 0), ('buzon.{}', 25, 0), ('casella.{}', 25, 0),
    ('boite.{}', 25, 0), ('inbox-server.{}', 25, 0), ('inboxserver.{}', 25, 0),
    ('outbox-server.{}', 25, 0), ('outboxserver.{}', 25, 0), ('mail-proxy1.{}', 25, 0),
    ('mail-proxy2.{}', 25, 0), ('smtp-proxy1.{}', 25, 0), ('smtp-proxy2.{}', 25, 0),
    ('email-proxy1.{}', 25, 0), ('email-proxy2.{}', 25, 0), ('mx3.mail.{}', 25, 0),
    ('mx4.mail.{}', 25, 0), ('smtp3.mail.{}', 25, 0), ('smtp4.mail.{}', 25, 0),
    ('relay3.mail.{}', 25, 0), ('relay4.mail.{}', 25, 0), ('mail.mail1.{}', 25, 0),
    ('mail.mail2.{}', 25, 0), ('smtp.smtp1.{}', 25, 0), ('smtp.smtp2.{}', 25, 0),
    ('mx.mx1.{}', 25, 0), ('mx.mx2.{}', 25, 0), ('relay.relay1.{}', 25, 0),
    ('relay.relay2.{}', 25, 0), ('securemail.{}', 587, 1), ('secure-email.{}', 587, 1),
    ('secureemail.{}', 587, 1), ('ssl-email.{}', 465, 1), ('sslemail.{}', 465, 1),
    ('tls-email.{}', 587, 1), ('tlsemail.{}', 587, 1), ('emailssl.{}', 587, 1),
    ('emailtls.{}', 587, 1), ('mail-ssl.{}', 587, 1), ('mailssl.{}', 587, 1),
    ('smtp-ssl.{}', 587, 1), ('smtpssl.{}', 587, 1), ('smtpsecure.{}', 587, 1),
    ('nodemail.{}', 25, 0), ('vipmail.{}', 25, 0), ('virtualsmtp.{}', 587, 0),
)

IMAP_SERVERS = (
    ("imap.{}", 993, 1), ("imap.{}", 143, 0), ("imap4.{}", 993, 1),
    ("imap4.{}", 143, 0), ("imap1.{}", 993, 1), ("imap1.{}", 143, 0),
    ("imap2.{}", 993, 1), ("imap2.{}", 143, 0), ("imap01.{}", 993, 1),
    ("imap01.{}", 143, 0), ("imap02.{}", 993, 1), ("imap02.{}", 143, 0),
    ("imap-mail.{}", 993, 1), ("imap-mail.{}", 143, 0), ("imapmail.{}", 993, 1),
    ("imapmail.{}", 143, 0), ("secure-imap.{}", 993, 1), ("secure-imap.{}", 143, 0),
    ("mail.{}", 993, 1), ("mail.{}", 143, 0), ("mail1.{}", 993, 1),
    ("mail1.{}", 143, 0), ("mail2.{}", 993, 1), ("mail2.{}", 143, 0),
    ("mail01.{}", 993, 1), ("mail01.{}", 143, 0), ("mail02.{}", 993, 1),
    ("mail02.{}", 143, 0), ("mailhost.{}", 993, 1), ("mailhost.{}", 143, 0),
    ("mailserver.{}", 993, 1), ("mailserver.{}", 143, 0), ("email.{}", 993, 1),
    ("email.{}", 143, 0), ("inbox.{}", 993, 1), ("inbox.{}", 143, 0),
    ("mailbox.{}", 993, 1), ("mailbox.{}", 143, 0), ("webmail.{}", 993, 1),
    ("webmail.{}", 143, 0), ("securemail.{}", 993, 1), ("securemail.{}", 143, 0),
    ("mx.{}", 993, 1), ("mx.{}", 143, 0), ("mx1.{}", 993, 1),
    ("mx1.{}", 143, 0), ("mx2.{}", 993, 1), ("mx2.{}", 143, 0),
    ("exchange.{}", 993, 1), ("exchange.{}", 143, 0), ("owa.{}", 993, 1),
    ("owa.{}", 143, 0),
)

POP3_SERVERS = (
    ("pop.{}", 995, 1), ("pop.{}", 110, 0), ("pop3.{}", 995, 1),
    ("pop3.{}", 110, 0), ("mail.{}", 995, 1), ("mail.{}", 110, 0),
    ("pop3s.{}", 995, 1), ("pop3s.{}", 110, 0), ("pop-mail.{}", 995, 1),
    ("pop-mail.{}", 110, 0), ("pop3-mail.{}", 995, 1), ("pop3-mail.{}", 110, 0),
    ("popmail.{}", 995, 1), ("popmail.{}", 110, 0), ("secure-pop.{}", 995, 1),
    ("secure-pop.{}", 110, 0), ("ssl-pop.{}", 995, 1), ("ssl-pop.{}", 110, 0),
    ("securemail.{}", 995, 1), ("securemail.{}", 110, 0), ("pop1.{}", 995, 1),
    ("pop1.{}", 110, 0), ("pop2.{}", 995, 1), ("pop2.{}", 110, 0),
    ("pop01.{}", 995, 1), ("pop01.{}", 110, 0), ("pop02.{}", 995, 1),
    ("pop02.{}", 110, 0), ("pop3-01.{}", 995, 1), ("pop3-01.{}", 110, 0),
    ("pop3-02.{}", 995, 1), ("pop3-02.{}", 110, 0), ("mail1.{}", 995, 1),
    ("mail1.{}", 110, 0), ("mail2.{}", 995, 1), ("mail2.{}", 110, 0),
    ("mail01.{}", 995, 1), ("mail01.{}", 110, 0), ("mail02.{}", 995, 1),
    ("mail02.{}", 110, 0), ("mailhost.{}", 995, 1), ("mailhost.{}", 110, 0),
    ("mailserver.{}", 995, 1), ("mailserver.{}", 110, 0), ("email.{}", 995, 1),
    ("email.{}", 110, 0), ("inbox.{}", 995, 1), ("inbox.{}", 110, 0),
    ("mailbox.{}", 995, 1), ("mailbox.{}", 110, 0), ("webmail.{}", 995, 1),
    ("webmail.{}", 110, 0), ("incoming.{}", 995, 1), ("incoming.{}", 110, 0),
    ("inbound.{}", 995, 1), ("inbound.{}", 110, 0), ("receive.{}", 995, 1),
    ("receive.{}", 110, 0), ("recv.{}", 995, 1), ("recv.{}", 110, 0),
    ("mx.{}", 995, 1), ("mx.{}", 110, 0), ("mx1.{}", 995, 1),
    ("mx1.{}", 110, 0), ("mx2.{}", 995, 1), ("mx2.{}", 110, 0),
)


# ==========================================================
# UTILITY FUNCTIONS
# ==========================================================

def get_unique_output(filename: str) -> str:
    """Return an unused filename."""
    path = Path(filename)
    if not path.exists():
        return str(path)
    counter = 2
    while True:
        new_path = path.with_name(f"{path.stem}-({counter}){path.suffix}")
        if not new_path.exists():
            return str(new_path)
        counter += 1


def clean_domain(line: str) -> Optional[str]:
    """Clean and validate domain."""
    domain = line.strip().strip('"').strip("'").lower()
    if not domain:
        return None
    
    domain = domain.replace("https://", "").replace("http://", "")
    
    if domain.startswith("www."):
        domain = domain[4:]
    
    domain = domain.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
    
    if "." not in domain:
        return None
    
    return domain


def iter_input_lines(path: Path) -> Iterator[str]:
    """Yield text values from TXT/LOG/CSV/XLSX input files."""
    suffix = path.suffix.lower()

    if suffix in {".txt", ".log"}:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            yield from handle
        return

    if suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                for value in row:
                    if value and value.strip():
                        yield value
        return

    if suffix == ".xlsx":
        try:
            from openpyxl import load_workbook
        except ImportError:
            raise RuntimeError("XLSX input requires openpyxl. Install: pip install openpyxl")
        
        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            for sheet in workbook.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    for value in row:
                        if value is not None:
                            yield str(value)
        finally:
            workbook.close()
        return

    raise RuntimeError(f"Unsupported input type: {path.suffix}")


# ==========================================================
# ASYNC PORT CHECKING
# ==========================================================

async def check_port(
    semaphore: asyncio.Semaphore,
    domain: str,
    template: str,
    port: int,
    ssl: int
) -> Optional[Tuple[str, str, int, int]]:
    """Check if port is open using async I/O."""
    host = template.format(domain)
    
    async with semaphore:
        try:
            # asyncio.open_connection is non-blocking and much faster than threads
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=TIMEOUT
            )
            writer.close()
            await writer.wait_closed()
            return (domain, host, port, ssl)
        except Exception:
            return None


async def check_domain(
    semaphore: asyncio.Semaphore,
    domain: str
) -> Tuple[List, List, List]:
    """Check all ports for a domain concurrently."""
    tasks = []
    
    # Create tasks for all port checks (hundreds per domain)
    for template, port, ssl in SMTP_SERVERS:
        tasks.append(check_port(semaphore, domain, template, port, ssl))
    
    for template, port, ssl in IMAP_SERVERS:
        tasks.append(check_port(semaphore, domain, template, port, ssl))
        
    for template, port, ssl in POP3_SERVERS:
        tasks.append(check_port(semaphore, domain, template, port, ssl))
    
    # Run all concurrently - the semaphore limits actual concurrent connections
    results = await asyncio.gather(*tasks)
    
    # Filter and categorize results
    smtp, imap, pop3 = [], [], []
    smtp_len = len(SMTP_SERVERS)
    imap_len = len(IMAP_SERVERS)
    
    for i, result in enumerate(results):
        if result is None:
            continue
        if i < smtp_len:
            smtp.append(result)
        elif i < smtp_len + imap_len:
            imap.append(result)
        else:
            pop3.append(result)
    
    return smtp, imap, pop3


# ==========================================================
# CSV WRITER WITH BUFFERING
# ==========================================================

class BufferedCSVWriter:
    """Buffers writes for performance."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.buffer: List[Tuple] = []
        self.seen: Set[Tuple] = set()
        self.total = 0
        
    def add(self, row: Tuple) -> bool:
        """Add row to buffer. Returns True if added."""
        if row in self.seen:
            return False
        self.seen.add(row)
        self.buffer.append(row)
        
        if len(self.buffer) >= WRITE_BUFFER:
            self.flush()
        return True
    
    def flush(self):
        """Write buffer to disk."""
        if not self.buffer:
            return
        
        with open(self.filepath, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(self.buffer)
        
        self.total += len(self.buffer)
        self.buffer.clear()
    
    def close(self):
        """Final flush."""
        self.flush()


# ==========================================================
# MAIN ASYNC PROCESSING
# ==========================================================

async def process_domains(
    files: List[Path],
    smtp_file: str,
    imap_file: str,
    pop3_file: str
):
    """Main async processing loop."""
    
    # Global semaphore limits total concurrent TCP connections
    semaphore = asyncio.Semaphore(CONCURRENCY)
    
    # Buffered writers
    smtp_writer = BufferedCSVWriter(smtp_file)
    imap_writer = BufferedCSVWriter(imap_file)
    pop3_writer = BufferedCSVWriter(pop3_file)
    
    # Stats
    total_read = 0
    valid_domains = 0
    duplicate_domains = 0
    checked = 0
    smtp_found = 0
    imap_found = 0
    pop3_found = 0
    
    seen_domains: Set[str] = set()
    
    # Process files
    for current_file in files:
        print(f"\n[INPUT] {current_file}")
        
        try:
            # Collect domains first to avoid memory issues with huge files
            domains_batch = []
            
            for line in iter_input_lines(current_file):
                total_read += 1
                domain = clean_domain(line)
                
                if not domain:
                    continue
                
                if domain in seen_domains:
                    duplicate_domains += 1
                    continue
                
                seen_domains.add(domain)
                valid_domains += 1
                domains_batch.append(domain)
                
                # Process in batches to avoid memory explosion
                if len(domains_batch) >= BATCH_SIZE:
                    await _process_batch(
                        domains_batch, semaphore,
                        smtp_writer, imap_writer, pop3_writer,
                        lambda: _print_status(
                            total_read, valid_domains, checked, 
                            smtp_found, imap_found, pop3_found
                        )
                    )
                    checked += len(domains_batch)
                    smtp_found = smtp_writer.total
                    imap_found = imap_writer.total
                    pop3_found = pop3_writer.total
                    domains_batch = []
            
            # Process remaining
            if domains_batch:
                await _process_batch(
                    domains_batch, semaphore,
                    smtp_writer, imap_writer, pop3_writer,
                    lambda: _print_status(
                        total_read, valid_domains, checked,
                        smtp_found, imap_found, pop3_found
                    )
                )
                checked += len(domains_batch)
                
        except Exception as error:
            print(f"\n[ERROR] Cannot read {current_file}: {error}")
    
    # Final flush
    smtp_writer.close()
    imap_writer.close()
    pop3_writer.close()
    
    # Final stats
    print("\n\n" + "=" * 70)
    print("[DONE]")
    print("=" * 70)
    print(f"Files processed       : {len(files):,}")
    print(f"Lines read            : {total_read:,}")
    print(f"Unique domains        : {valid_domains:,}")
    print(f"Duplicate domains     : {duplicate_domains:,}")
    print(f"Domains checked       : {checked:,}")
    print(f"SMTP found            : {smtp_writer.total:,}")
    print(f"IMAP found            : {imap_writer.total:,}")
    print(f"POP3 found            : {pop3_writer.total:,}")
    print("\nOutput files:")
    print(f"  SMTP : {smtp_file}")
    print(f"  IMAP : {imap_file}")
    print(f"  POP3 : {pop3_file}")
    print("=" * 70)


async def _process_batch(
    domains: List[str],
    semaphore: asyncio.Semaphore,
    smtp_writer: BufferedCSVWriter,
    imap_writer: BufferedCSVWriter,
    pop3_writer: BufferedCSVWriter,
    status_callback
):
    """Process a batch of domains concurrently."""
    tasks = [check_domain(semaphore, domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    
    for smtp, imap, pop3 in results:
        for row in smtp:
            if smtp_writer.add(row):
                pass
        for row in imap:
            if imap_writer.add(row):
                pass
        for row in pop3:
            if pop3_writer.add(row):
                pass
    
    status_callback()


def _print_status(read, valid, checked, smtp, imap, pop3):
    """Print status line."""
    print(
        f"Read:{read:,} Checked:{checked:,} SMTP:{smtp:,} IMAP:{imap:,} POP3:{pop3:,}",
        end="\r",
        flush=True
    )


# ==========================================================
# ENTRY POINT
# ==========================================================

def main():
    # Input file/folder
    while True:
        input_file = input("Please input file or folder: ").strip().strip('"')
        if not input_file:
            print("[ERROR] Please enter a file or folder.")
            continue
        
        input_path = Path(input_file)
        
        if input_path.is_file():
            files = [input_path]
            break
        elif input_path.is_dir():
            files = sorted(
                p for p in input_path.iterdir()
                if p.is_file() and p.suffix.lower() in {".txt", ".log", ".csv", ".xlsx"}
            )
            if files:
                break
            print("[ERROR] No .txt, .log, .csv or .xlsx files found.")
            continue
        
        print(f"[ERROR] File or folder not found: {input_path}")
    
    # Output files
    smtp_output = get_unique_output(SMTP_OUTPUT)
    imap_output = get_unique_output(IMAP_OUTPUT)
    pop3_output = get_unique_output(POP3_OUTPUT)
    
    # Write headers
    for filepath in [smtp_output, imap_output, pop3_output]:
        with open(filepath, "w", encoding="utf-8", newline="") as f:
            f.write("domain,server,port,ssl\n")
    
    # Display config
    print()
    print("=" * 70)
    print("SMTP + IMAP + POP3 SERVER CHECKER - ASYNC OPTIMIZED")
    print("=" * 70)
    print("Input:")
    for file in files:
        print(f"  - {file}")
    print()
    print(f"Concurrency : {CONCURRENCY:,} connections")
    print(f"Timeout     : {TIMEOUT}s")
    print(f"Batch size  : {BATCH_SIZE}")
    print()
    print("Output:")
    print(f"  SMTP : {smtp_output}")
    print(f"  IMAP : {imap_output}")
    print(f"  POP3 : {pop3_output}")
    print("=" * 70)
    print()
    
    # Run async main
    asyncio.run(process_domains(files, smtp_output, imap_output, pop3_output))


if __name__ == "__main__":
    main()
