# Mail Server Checker

A Python command-line tool that discovers and verifies public SMTP, IMAP, and POP3 endpoints for domains in a text file. It resolves candidate hostnames before opening connections, performs a protocol handshake, and writes separate timestamped CSV files for each mail protocol.

The checker does not log in, send messages, read mail, or test whether a mailbox exists.

## Features

- **Fast and all modes:** Start with likely mail hostnames, or use the larger hostname lists included in the script.
- **Published DNS records:** Finds inbound SMTP hosts from MX records. All mode also checks relevant SRV records when `dnspython` is installed.
- **Protocol verification:** Uses SMTP EHLO, IMAP CAPABILITY, and POP3 NOOP rather than reporting every open TCP port as a mail server.
- **TLS reporting:** Records whether the successful check used implicit TLS, STARTTLS, or no verified TLS.
- **Concurrent checks:** Resolves each candidate hostname once, then probes its applicable ports through a bounded worker pool.
- **CSV output:** Writes `smtp(YYYY-MM-DD_HH-MM-SS).csv`, `imap(YYYY-MM-DD_HH-MM-SS).csv`, and `pop3(YYYY-MM-DD_HH-MM-SS).csv` in the current working directory.

## Requirements

- Python 3.9 or newer
- [`dnspython`](https://pypi.org/project/dnspython/) for MX and SRV discovery (recommended)

Install the DNS dependency on Windows:

```powershell
py -m pip install dnspython
```

The script can run without `dnspython`, but it will skip MX and SRV discovery and use the system resolver to check candidate hostnames.

## Quick start

1. Save `mail_server_checker_fixed.py` and create a UTF-8 text file with one domain per line:

   ```text
   example.com
   example.org
   # Comments and empty lines are ignored
   ```

2. Run the checker from PowerShell:

   ```powershell
   py mail_server_checker_fixed.py
   ```

3. Enter the file path, scan mode, and thread count when prompted:

   ```text
   Enter domain TXT file path: E:\Domains\domains.txt
   Scan mode [fast/all] (default fast): fast
   Threads [100, max 200]: 100
   ```

A quoted Windows file path is accepted. Bare domains and URLs are normalized to hostnames. Invalid lines are skipped.

On systems where `py` is unavailable, use `python mail_server_checker_fixed.py` and `python -m pip install dnspython`.

## Scan modes

| Mode | Discovery | Use when |
| --- | --- | --- |
| `fast` | Checks the domain, published MX hosts, and a small set of likely SMTP, IMAP, and POP3 hostnames. | You want results across many domains with fewer DNS queries and connection attempts. |
| `all` | Checks the domain, published MX hosts, all supplied hostname prefixes, and published mail SRV records. | You need broader hostname coverage and can allow substantially more time and DNS traffic. |

All mode does not guarantee discovery of every mail service. Providers can use hostnames outside the supplied patterns, require authentication, or block probes. MX records identify inbound mail exchangers; they do not establish an SMTP submission endpoint.

The script uses a two-second timeout for network operations, up to five published MX hosts per domain, and a default of 100 workers. These settings are near the top of the script. More workers can increase throughput on slow networks, but the 200-worker prompt limit is a script setting rather than a Python limit.

## Output format

Each CSV starts with the following columns:

| Column | Meaning |
| --- | --- |
| `Domain` | Normalized input domain. |
| `Host` | Hostname that answered the protocol check. |
| `Port` | Port on which the check succeeded. |
| `SSL` | `1` if TLS was successfully negotiated; otherwise `0`. |
| `Security` | `implicit_tls`, `starttls`, or `none`. |
| `Verification` | `protocol_handshake` for a successful protocol response. |

Example SMTP row:

```csv
Domain,Host,Port,SSL,Security,Verification
example.com,smtp.example.com,587,1,starttls,protocol_handshake
```

The example is illustrative. A row confirms that the endpoint responded to the relevant protocol check at scan time. It does **not** confirm valid credentials, mailbox access, permission to relay messages, deliverability, or the domain's configured outbound provider. If no endpoint is verified for a protocol, its CSV contains only the header row.

## How verification works

| Protocol | Ports checked | Successful response |
| --- | --- | --- |
| SMTP | `25`, `465`, `587`; all mode also checks `2525` and `26` for supplied hostname patterns. | An EHLO response. On `587`, advertised STARTTLS must also succeed. |
| IMAP | `993`, `143` | A valid CAPABILITY response, with STARTTLS on `143` when advertised. |
| POP3 | `995`, `110` | A valid NOOP response, with STLS on `110` when advertised. |

TLS connections use Python's default certificate validation. A service can therefore be reachable but absent from the CSV if its certificate does not validate for the hostname being checked.

## Troubleshooting

- **No MX or SRV results:** Install `dnspython` in the same Python environment used to run the script: `py -m pip install dnspython`.
- **Empty CSVs:** Try a small known domain list first. Network filters, DNS failures, certificate mismatches, and the two-second timeout can all affect results. You can raise `TIMEOUT` in the script for slow networks.
- **All mode takes too long:** Use fast mode. All mode contains more than a thousand SMTP hostname prefixes before port checks.
- **`py` is not recognized:** Try `python` instead, or install Python with the Windows launcher.

## Scope of verification

This is a service-discovery tool. It does not authenticate, test passwords, submit email, or access message contents. Results describe what responded from the machine and network where you ran the check; connectivity and server configuration can change later.
