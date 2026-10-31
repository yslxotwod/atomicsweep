"""Tier D — self-hosted software that ended up facing the internet.

These are not telecom devices. They are the same mistake in a different place:
something with a management plane was installed to be reached from inside and
then answered from outside. They are in this bench because the fingerprint is
cheap and unambiguous — the product names itself in its own reply, so a `hit`
needs no exploit to be true.

The rule carried over from the ACS work applies hardest here: **a challenge is
not a breach**. Elasticsearch answering `SecurityException`, Redis answering
`-NOAUTH`, a Redfish root that wants credentials — all of those are `open` with
the product named, never `hit`. `hit` means the box identified itself *and* the
reply that identified it needed no credentials.
"""

from __future__ import annotations

import re

from core import net
from classes.base import SweepClass, res
from classes import netfp as fp

class Hypervisors(SweepClass):
    id = "d1_hypervisor"
    title = "Hypervisors (ESXi / Proxmox / Nutanix)"
    tier = "D"
    proto = "https"
    ports = (443, 902, 8006, 9440, 5985)
    population = "hosting-cloud"
    desc = ("Hosts that publish their own console. ESXi names itself in the SDK "
            "path and the login title, Proxmox in /api2/json/version, Nutanix "
            "Prism in its own title. Port 902 alone is only evidence of a vSphere "
            "authd listener, which is why it is graded `open`.")
    geo_hint = (48.0, 10.0)
    CONTROLS = (("176.106.121.20", 80, "hit"),)

    TLS = {443, 8006, 9440}

    def probe(self, ip, port, timeout=3.0, tls=None):
        tls = (port in self.TLS) if tls is None else tls
        if port == 902:
            p = net.tcp_connect(ip, port, timeout=timeout)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            if p.state != net.OPEN:
                return res("error", "", p.detail)
            return res("open", "vSphere authd listener", "port 902 accepts", p.rtt)

        if port == 5985:
            r = fp.get(ip, 5985, "/wsman", timeout=timeout, tls=False)
            s = fp.server_of(r)
            if r.state == net.REFUSED:
                return res("refused", "", "RST")
            if r.state == net.UNPROVEN:
                return res("unproven", "", r.detail)
            if "microsoft-httpapi" in s.lower():
                return res("hit", "WinRM (Hyper-V host candidate)",
                           f"{s} status={r.status}")
            return res("open", "", f"status={r.status}", None)

        path, marker = "/", ""
        r = fp.get(ip, port, path, timeout=timeout, tls=tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)

        if port == 8006:
            v = fp.get(ip, 8006, "/api2/json/version", timeout=timeout, tls=True)
            j = fp.jbody(v.text) or {}
            d = j.get("data") if isinstance(j, dict) else None
            if isinstance(d, dict) and d.get("release"):
                return res("hit", "Proxmox VE",
                           f"release={d.get('release')} version={d.get('version', '')}",
                           None)
            t = fp.title(r.text)
            if t:
                return res("open", "", f"tls title={t!r} status={r.status}", None)
            return res("open", "", f"tls status={r.status}", None)

        body = r.text or ""
        low = body.lower()
        t = fp.title(body)

        if "vmware esxi" in low or "vmware" in fp.server_of(r).lower():
            return res("hit", "VMware ESXi", f"title={t!r}", None)
        if "nutanix" in low or "prism" in t.lower():
            return res("hit", "Nutanix Prism", f"title={t!r}", None)
        if "xenserver" in low or "citrix hypervisor" in low:
            return res("hit", "Citrix XenServer", f"title={t!r}", None)
        if "harvester" in low and "rancher" in low:
            return res("hit", "SUSE Harvester", f"title={t!r}", None)

        s = fp.get(ip, port, "/sdk", timeout=timeout, tls=tls, max_body=8192)
        if s.state == net.OPEN and ("vmware" in (s.text or "").lower()
                                    or "vimservice" in (s.text or "").lower()):
            return res("hit", "VMware ESXi", "SDK endpoint names vim", None)

        if fp.looks_auth(r) and t:
            return res("open", "", f"auth challenge, title={t!r}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

class ContainerApis(SweepClass):
    id = "d2_container"
    title = "Docker / Kubernetes / etcd APIs"
    tier = "D"
    proto = "http"
    ports = (2375, 2376, 6443, 10250, 10255, 2379, 4646, 9000)
    population = "hosting-cloud"
    desc = ("An unauthenticated Docker socket is remote root by design; an open "
            "kubelet lets anyone run a pod on the node; anonymous etcd hands over "
            "every cluster secret. Each of these names itself in its reply, so the "
            "fingerprint is the proof.")
    geo_hint = (37.0, -122.0)
    CONTROLS = ()

    TLS = {2376, 6443, 10250}

    def probe(self, ip, port, timeout=3.0, tls=None):
        tls = (port in self.TLS) if tls is None else tls

        if port in (2375, 2376):
            r = fp.get(ip, port, "/_ping", timeout=timeout, tls=tls)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            t = (r.text or "").strip()
            if t.startswith("OK"):
                v = fp.get(ip, port, "/version", timeout=timeout, tls=tls)
                j = fp.jbody(v.text) or {}
                ver = j.get("Version", "") if isinstance(j, dict) else ""
                how = "tls" if tls else "PLAINTEXT"
                return res("hit", "Docker Engine API",
                           f"{how} /_ping=OK Version={ver}", None)
            if fp.looks_auth(r):
                return res("open", "Docker (auth required)", f"status={r.status}", None)
            return res("open", "", f"status={r.status}", None)

        if port == 6443:
            r = fp.get(ip, 6443, "/version", timeout=timeout, tls=True)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and j.get("gitVersion"):
                return res("hit", "Kubernetes API server",
                           f"gitVersion={j.get('gitVersion')}", None)
            if fp.looks_auth(r) or r.status in (401, 403):
                return res("open", "Kubernetes API (auth required)",
                           f"status={r.status}", None)
            return res("open", "", f"status={r.status}", None)

        if port == 10250:
            r = fp.get(ip, 10250, "/healthz", timeout=timeout, tls=True)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            if (r.text or "").strip().lower().startswith("ok"):
                p = fp.get(ip, 10250, "/pods", timeout=timeout, tls=True)
                anon = p.status == 200 and '"items"' in (p.text or "")
                return res("hit" if anon else "open", "kubelet",
                           ("/pods readable ANONYMOUSLY" if anon
                            else f"/pods status={p.status} (auth)"), None)
            if fp.looks_auth(r):
                return res("open", "kubelet (auth required)", f"status={r.status}", None)
            return res("open", "", f"status={r.status}", None)

        if port == 10255:
            r = fp.get(ip, 10255, "/pods", timeout=timeout, tls=False)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            if r.status == 200 and '"items"' in (r.text or ""):
                return res("hit", "kubelet read-only port", "/pods anonymous", None)
            return res("open", "", f"status={r.status}", None)

        if port == 2379:
            r = fp.get(ip, 2379, "/version", timeout=timeout, tls=False)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and ("etcdserver" in j or "etcdcluster" in j):
                return res("hit", "etcd", f"etcdserver={j.get('etcdserver')}", None)
            return res("open", "", f"status={r.status}", None)

        if port == 4646:
            r = fp.get(ip, 4646, "/v1/status/leader", timeout=timeout, tls=False)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            t = (r.text or "").strip()
            if r.status == 200 and t.startswith('"'):
                return res("hit", "HashiCorp Nomad", f"leader={t[:60]}", None)
            return res("open", "", f"status={r.status}", None)

        r = fp.get(ip, 9000, "/api/system/status", timeout=timeout, tls=False)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        j = fp.jbody(r.text) or {}
        if isinstance(j, dict) and j.get("Version"):
            return res("hit", "Portainer", f"version={j.get('Version')}", None)
        return res("open", "", f"status={r.status}", None)

OPS_TABLE = [
    ("Grafana", ["grafana"]),
    ("Prometheus", ["prometheus"]),
    ("Jenkins", ["jenkins"]),
    ("Kibana", ["kibana"]),
    ("RabbitMQ management", ["rabbitmq"]),
    ("Zabbix", ["zabbix"]),
    ("Netdata", ["netdata"]),
    ("Portainer", ["portainer"]),
    ("Apache Airflow", ["airflow"]),
    ("GitLab", ["gitlab"]),
    ("SonarQube", ["sonarqube", "sonar"]),
    ("Nexus / Artifactory", ["nexus repository", "artifactory"]),
    ("Rundeck", ["rundeck"]),
    ("Apache NiFi", ["nifi"]),
    ("Kibana / OpenSearch Dashboards", ["opensearch dashboards"]),
]

class Observability(SweepClass):
    id = "d3_ops"
    title = "Jenkins / Grafana / Prometheus / Kibana"
    tier = "D"
    proto = "http"
    ports = (8080, 3000, 9090, 5601, 15672, 9100, 10050)
    population = "hosting-cloud"
    desc = ("The operations plane of a company: build pipelines, dashboards, "
            "metrics, logs. Jenkins hands over code execution, Grafana leaks every "
            "data source and its credentials, Prometheus dumps the whole target "
            "list. All identified from content, never from the port.")
    geo_hint = (51.5, 0.0)
    CONTROLS = (("demo.promlabs.com", 9090, "hit"),
                ("play.grafana.org", 443, "hit", True),
                ("ci.jenkins.io", 443, "hit", True))

    TLS = {443, 8443}

    def probe(self, ip, port, timeout=3.0, tls=None):
        tls = (port in self.TLS) if tls is None else tls
        if port == 10050:
            p = net.tcp_banner(ip, port, timeout=timeout,
                               send=b"ZBXD\x01\x09\x00\x00\x00\x00\x00\x00\x00agent.ping",
                               settle=1.2)
            if p.state == net.REFUSED:
                return res("refused", "", "RST")
            if p.state == net.UNPROVEN:
                return res("unproven", "", p.detail)
            if p.data and p.data[:4] == b"ZBXD":
                return res("hit", "Zabbix agent", "ZBXD reply", p.rtt)
            return res("open", "", "accepts, no ZBXD reply", p.rtt)

        if port == 9100:
            r = fp.get(ip, port, "/metrics", timeout=timeout, tls=tls, max_body=32768)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            b = r.text or ""
            if "node_exporter" in b or b.startswith("# HELP node_"):
                return res("hit", "Prometheus node_exporter", "/metrics open", None)
            if "# HELP" in b:
                return res("hit", "Prometheus exporter", "/metrics open", None)
            return res("open", "", f"status={r.status}", None)

        if port == 9090:
            r = fp.get(ip, port, "/api/v1/status/buildinfo", timeout=timeout, tls=tls)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            j = fp.jbody(r.text) or {}
            d = j.get("data") if isinstance(j, dict) else None
            if isinstance(d, dict) and d.get("version"):
                return res("hit", "Prometheus", f"version={d.get('version')}", None)
            h = fp.get(ip, port, "/-/healthy", timeout=timeout, tls=tls)
            if (h.text or "").strip().lower().startswith("prometheus"):
                return res("hit", "Prometheus", "/-/healthy", None)
            return res("open", "", f"status={r.status}", None)

        if port == 3000:
            r = fp.get(ip, port, "/api/health", timeout=timeout, tls=tls)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and ("database" in j or "commit" in j):
                return res("hit", "Grafana",
                           f"version={j.get('version', '')} db={j.get('database')}", None)
            return res("open", "", f"status={r.status}", None)

        if port == 8080:
            r = fp.get(ip, port, "/", timeout=timeout, tls=tls)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            jv = r.headers.get("x-jenkins")
            if jv or "jenkins" in (r.text or "").lower()[:4000]:
                return res("hit", "Jenkins", f"X-Jenkins={jv or 'title'}", None)
            if fp.looks_auth(r):
                return res("open", "", f"status={r.status} (auth)", None)
            return res("open", "", f"status={r.status}", None)

        if port == 5601:
            r = fp.get(ip, port, "/api/status", timeout=timeout, tls=tls)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and isinstance(j.get("version"), dict):
                return res("hit", "Kibana",
                           f"version={j['version'].get('number', '')}", None)
            return res("open", "", f"status={r.status}", None)

        if port == 15672:
            return self._rabbit(ip, port, timeout, tls)

        return self._by_content(ip, port, timeout, tls)

    def _by_content(self, ip, port, timeout, tls):
        r = fp.get(ip, port, "/api/v1/status/buildinfo", timeout=timeout, tls=tls)
        if r.state == net.OPEN:
            j = fp.jbody(r.text) or {}
            d = j.get("data") if isinstance(j, dict) else None
            if isinstance(d, dict) and d.get("version"):
                return res("hit", "Prometheus", f"version={d.get('version')}", None)

        r = fp.get(ip, port, "/api/health", timeout=timeout, tls=tls)
        if r.state == net.OPEN:
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and ("database" in j or "commit" in j):
                return res("hit", "Grafana",
                           f"version={j.get('version', '')} db={j.get('database')}", None)

        r = fp.get(ip, port, "/", timeout=timeout, tls=tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        jv = r.headers.get("x-jenkins")
        body = r.text or ""
        if jv:
            return res("hit", "Jenkins", f"X-Jenkins={jv}", None)
        if "jenkins" in body.lower()[:4000]:
            return res("hit", "Jenkins", f"title={fp.title(body)!r}", None)
        if "/rabbitmq" in body.lower() or "rabbitmq management" in body.lower():
            return res("hit", "RabbitMQ management", "root names rabbitmq", None)
        t = fp.title(body)
        named = self.match_any(body[:4000] + " " + t, OPS_TABLE)
        if named:
            return res("hit", named,
                       f"public {t!r} login, status={r.status}", None)
        if fp.looks_auth(r):
            return res("open", "", f"auth challenge status={r.status}", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

    def _rabbit(self, ip, port, timeout, tls):
        r = fp.get(ip, port, "/api/overview", timeout=timeout, tls=tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        j = fp.jbody(r.text) or {}
        if isinstance(j, dict) and j.get("rabbitmq_version"):
            return res("hit", "RabbitMQ management",
                       f"version={j.get('rabbitmq_version')} ANONYMOUS", None)
        if fp.looks_auth(r):
            return res("open", "RabbitMQ management (auth required)",
                       f"status={r.status}", None)
        return res("open", "", f"status={r.status}", None)

MONGO_HELLO = (b"\x3a\x00\x00\x00"
               b"\x01\x00\x00\x00"
               b"\x00\x00\x00\x00"
               b"\xd4\x07\x00\x00"
               b"\x00\x00\x00\x00"
               b"admin.$cmd\x00"
               b"\x00\x00\x00\x00"
               b"\x01\x00\x00\x00"
               b"\x13\x00\x00\x00"
               b"\x10ismaster\x00"
               b"\x01\x00\x00\x00"
               b"\x00")

class DataStores(SweepClass):
    id = "d4_datastore"
    title = "Elasticsearch / Redis / MongoDB / CouchDB"
    tier = "D"
    proto = "tcp"
    ports = (9200, 6379, 27017, 5984, 8123, 8086, 11211)
    population = "hosting-cloud"
    desc = ("Databases reachable without a credential. Each names itself in its own "
            "protocol reply. A store that answers with an auth error is recorded as "
            "`open` with the product named — it is a database, not a breach.")
    geo_hint = (35.0, 139.0)
    CONTROLS = ()

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 6379:
            return self._redis(ip, timeout)
        if port == 27017:
            return self._mongo(ip, timeout)
        if port == 11211:
            return self._memcached(ip, timeout)
        return self._http(ip, port, timeout, tls)

    def _redis(self, ip, timeout):
        p = net.tcp_banner(ip, 6379, timeout=timeout, send=b"PING\r\n", settle=1.0)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state == net.UNPROVEN:
            return res("unproven", "", p.detail)
        b = (p.data or b"").decode("latin-1")
        if b.startswith("+PONG"):
            return res("hit", "Redis", "PING -> +PONG, NO AUTH", p.rtt)
        if b.startswith("-NOAUTH") or b.startswith("-WRONGPASS"):
            return res("open", "Redis (auth required)", b.strip()[:80], p.rtt)
        if b.startswith("-DENIED"):
            return res("open", "Redis (protected mode)", b.strip()[:80], p.rtt)
        if b.startswith("-"):
            return res("open", "Redis-like", b.strip()[:80], p.rtt)
        return res("open", "", f"reply={b[:60]!r}", p.rtt)

    def _mongo(self, ip, timeout):
        p = net.tcp_banner(ip, 27017, timeout=timeout, send=MONGO_HELLO, settle=1.2)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state == net.UNPROVEN:
            return res("unproven", "", p.detail)
        d = p.data or b""
        if b"ismaster" in d or b"isWritablePrimary" in d:
            ver = fp.printable(d, 4, 60)
            return res("hit", "MongoDB", f"isMaster answered without auth ({ver})", p.rtt)
        if b"unauthorized" in d.lower() or b"AuthenticationFailed" in d:
            return res("open", "MongoDB (auth required)", "auth error", p.rtt)
        return res("open", "", f"{len(d)} bytes, no isMaster", p.rtt)

    def _memcached(self, ip, timeout):
        p = net.tcp_banner(ip, 11211, timeout=timeout, send=b"stats\r\n", settle=1.0)
        if p.state == net.REFUSED:
            return res("refused", "", "RST")
        if p.state == net.UNPROVEN:
            return res("unproven", "", p.detail)
        b = (p.data or b"").decode("latin-1")
        if "STAT pid" in b or "STAT version" in b:
            ver = re.search(r"STAT version (\S+)", b)
            return res("hit", "memcached",
                       f"stats open version={ver.group(1) if ver else '?'}", p.rtt)
        return res("open", "", f"reply={b[:60]!r}", p.rtt)

    def _http(self, ip, port, timeout, tls=None):
        r = fp.get(ip, port, "/", timeout=timeout, tls=bool(tls))
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        b = r.text or ""
        j = fp.jbody(b)

        if port == 9200:
            if isinstance(j, dict) and j.get("cluster_name"):
                v = j.get("version") if isinstance(j.get("version"), dict) else {}
                kind = "OpenSearch" if "distribution" in v else "Elasticsearch"
                anon = not fp.looks_auth(r)
                return res("hit" if anon else "open", kind,
                           f"cluster={j.get('cluster_name')} "
                           f"version={v.get('number', '')}", None)
            if isinstance(j, dict) and "error" in j:
                return res("open", "Elasticsearch (secured)", "error reply", None)

        if port == 5984:
            if isinstance(j, dict) and str(j.get("couchdb", "")).lower() == "welcome":
                return res("hit", "CouchDB", f"version={j.get('version', '')}", None)

        if port == 8123:
            p = fp.get(ip, port, "/ping", timeout=timeout, tls=bool(tls))
            if (p.text or "").strip() == "Ok.":
                return res("hit", "ClickHouse", "/ping -> Ok.", None)

        if port == 8086:
            v = r.headers.get("x-influxdb-version") or r.headers.get("x-influxdb-build")
            if v:
                return res("hit", "InfluxDB", f"X-Influxdb-Version={v}", None)

        return res("open", "", f"status={r.status}", None)

class ObjectStores(SweepClass):
    id = "d5_objectstore"
    title = "MinIO / Vault / S3-compatible storage"
    tier = "D"
    proto = "http"
    ports = (9000, 9001, 8200, 9333)
    population = "hosting-cloud"
    desc = ("Object storage and secret stores. MinIO answers AccessDenied with an "
            "S3 error document that names itself; Vault's /v1/sys/health reports "
            "seal state and version with no credential. An unsealed, initialised "
            "Vault on the internet is the whole company's secrets behind one token.")
    geo_hint = (40.0, -74.0)
    CONTROLS = (("play.min.io", 443, "hit", True),)

    TLS = {443, 9001, 8443}

    def probe(self, ip, port, timeout=3.0, tls=None):
        tls = (port in self.TLS) if tls is None else tls
        if port == 8200:
            r = fp.get(ip, port, "/v1/sys/health", timeout=timeout, tls=tls)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and "initialized" in j:
                return res("hit", "HashiCorp Vault",
                           f"version={j.get('version', '')} "
                           f"initialized={j.get('initialized')} "
                           f"sealed={j.get('sealed')} status={r.status}", None)
            return res("open", "", f"status={r.status}", None)

        if port == 9333:
            r = fp.get(ip, port, "/dir/status", timeout=timeout, tls=tls)
            why = fp.state_from(r)
            if why:
                return res(why, "", r.detail)
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and ("Topology" in j or "Version" in j):
                return res("hit", "SeaweedFS master", "dir/status", None)
            return res("open", "", f"status={r.status}", None)

        h = fp.get(ip, port, "/minio/health/live", timeout=timeout, tls=tls)
        if h.state == net.OPEN and h.status == 200:
            hk = " ".join(str(k).lower() for k in h.headers) + " " + \
                 " ".join(str(v).lower() for v in h.headers.values())
            root = fp.get(ip, port, "/", timeout=timeout, tls=tls)
            rk = (root.text or "").lower() + " " + " ".join(
                str(k).lower() for k in root.headers)
            if "minio" in hk:
                return res("hit", "MinIO",
                           f"health/live 200, server={h.headers.get('x-minio-server')}", None)
            if "minio" in rk:
                return res("hit", "MinIO", "root names minio", None)
            if "x-amz-request-id" in hk or "x-amz-bucket-region" in hk:
                return res("hit", "S3-compatible object storage",
                           "health path + x-amz headers", None)
            return res("open", "",
                       f"200 on /minio/health/live but no MinIO marker "
                       f"(status={root.status})", None)

        r = fp.get(ip, port, "/", timeout=timeout, tls=tls)
        why = fp.state_from(r)
        if why:
            return res(why, "", r.detail)
        b = r.text or ""
        low = b.lower()
        t = fp.title(b)
        if "minio" in low or "minio" in t.lower():
            return res("hit", "MinIO console", f"title={t!r}", None)
        if "<code>accessdenied</code>" in low or "accessdenied" in low and "<error>" in low:
            return res("hit", "S3-compatible object storage",
                       f"S3 error document status={r.status}", None)
        if fp.jbody(b) and isinstance(fp.jbody(b), dict):
            j = fp.jbody(b)
            if "minio" in str(j).lower():
                return res("hit", "MinIO", "JSON names minio", None)
        return res("open", "", f"status={r.status} title={t!r}", None)

IPMI_AUTH_CAPS = (b"\x06\x00\xff\x07"
                  b"\x00\x00\x00\x00"
                  b"\x00\x00\x00\x00"
                  b"\x00\x00"
                  b"\x20"
                  b"\x18\xc8\x81\x00\x38\x8e\x04\xb5\x00")

class Bmc(SweepClass):
    id = "d6_bmc"
    title = "BMC / IPMI / Redfish"
    tier = "D"
    proto = "redfish"
    ports = (443, 80, 623)
    population = "hosting-cloud"
    desc = ("The management chip on a server: iDRAC, iLO, Supermicro, Lenovo XCC. "
            "Redfish tells you the vendor and model without a credential; IPMI "
            "answers a session-less capabilities request over UDP. A BMC is "
            "out-of-band by definition, so anything reachable here bypasses the "
            "operating system entirely.")
    geo_hint = (47.0, 8.0)
    CONTROLS = ()

    def targets(self, ips):
        for ip in ips:
            yield ip, 443
            yield ip, 623

    def probe(self, ip, port, timeout=3.0, tls=None):
        if port == 623:
            p = net.udp_exchange(ip, 623, IPMI_AUTH_CAPS, timeout=timeout, tries=2)
            if p.state == net.UNPROVEN:
                return res("unproven", "", "silent (UDP absence is not closure)")
            if p.state != net.OPEN:
                return res("error", "", p.detail)
            d = p.data or b""
            if d[:4] == b"\x06\x00\xff\x07":
                return res("hit", "IPMI (RMCP+ reachable)",
                           f"{len(d)}B capabilities reply", p.rtt)
            return res("open", "", f"{len(d)}B reply, not RMCP", p.rtt)

        for attempt in ((tls,) if tls is not None else (True, False)):
            r = fp.get(ip, port, "/redfish/v1", timeout=timeout, tls=attempt,
                       max_body=32768)
            if r.state == net.REFUSED:
                if not attempt:
                    return res("refused", "", "RST")
                continue
            if r.state == net.UNPROVEN:
                continue
            if r.state != net.OPEN:
                continue
            j = fp.jbody(r.text) or {}
            if isinstance(j, dict) and ("RedfishVersion" in j or "/redfish/v1/" in str(j)):
                vendor = str(j.get("Vendor", "") or j.get("Oem", ""))[:60]
                prod = str(j.get("Product", ""))[:60]
                anon = r.status == 200
                return res("hit" if anon else "open", "Redfish BMC",
                           f"vendor={vendor} product={prod} status={r.status}", None)
            t = fp.title(r.text)
            body = (r.text or "").lower()
            for name, keys in (("Dell iDRAC", ("idrac",)),
                               ("HPE iLO", ("ilo", "integrated lights-out")),
                               ("Supermicro BMC", ("supermicro", "ipmi")),
                               ("Lenovo XCC", ("xclarity", "lenovo")),
                               ("ASUS ASMB", ("asmb",)),
                               ("Inspur BMC", ("inspur",))):
                if any(k in body for k in keys) or (t and any(k in t.lower() for k in keys)):
                    return res("hit", name, f"title={t!r}", None)
            if fp.looks_auth(r):
                return res("open", "", f"auth challenge status={r.status}", None)
        return res("open", "", "answered, unidentified", None)

CLASSES = [Hypervisors(), ContainerApis(), Observability(), DataStores(),
           ObjectStores(), Bmc()]
