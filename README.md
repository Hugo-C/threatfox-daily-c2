# ThreatFox daily C2

The goal of this repository is to fetch recent C2 hosts from [ThreatFox](https://threatfox.abuse.ch/) so as to submit them to [jarm.online](https://jarm.online/).  
This information will then be used to constitute a database of malicious JARM hash used by C2 families.

## Stack used
[![Stack](https://skillicons.dev/icons?i=python,cloudflare,workers)](https://skillicons.dev)

* [Cloudflare Workers](https://workers.cloudflare.com/) to run the underlying cloud functions on a given schedule
* [Cloudflare KV](https://developers.cloudflare.com/kv/) to store the IOCs already processed

## Developpement

Install [just](https://github.com/casey/just) with `cargo install just` then run:
```shell
just lint
```
to run the linters
```shell
just dev
```
to run the worker locally