from datetime import datetime
import json
from typing import Self
import logging

# We can't use requests/httpx, we have to rely on JS to do HTTP requests
# See https://github.com/cloudflare/workers-sdk/issues/5608
# See https://pyodide.org/en/stable/usage/api/python-api/http.html#pyodide.http.pyfetch
from pyodide.http import pyfetch

THREAT_FOX_API = "https://threatfox-api.abuse.ch/api/v1/"
JARM_ONLINE_API = "https://jarm.online/api/v1/jarm"

C2_THREAT_TYPE = "botnet_cc"
IP_PORT_FORMAT = "ip:port"

THREATFOX_DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"
KV_CACHE_KEY = "first_seen_processed"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class IocsAcknowledged:
    def __init__(self):
        self.processed = set()

    @staticmethod
    def compute_ioc_key(ioc: dict):
        keys = []
        for k, v in sorted(ioc.items()):
            keys.append(f"{k}:{v}")
        return "-".join(keys)

    def add(self, ioc: dict):
        self.processed.add(self.compute_ioc_key(ioc))

    def __contains__(self, ioc: dict):
        key = self.compute_ioc_key(ioc)
        return key in self.processed

    def __len__(self):
        return len(self.processed)

    def __repr__(self):
        result = f"{self.__class__.__name__}: {len(self)} iocs"
        for key in self.processed:
            result += f"\n{key}"
        return result


class ThreatFoxJarmer:
    def __init__(self, kv_cache, max_ioc_to_compute: int):
        """Should not be called directly, use create instead"""
        self.acknowledged = IocsAcknowledged()
        self.kv_cache = kv_cache
        self.max_ioc_to_compute = max_ioc_to_compute
        self.ioc_first_seen_processed_up_to = None  # to be filled async by create

    @classmethod
    async def create(cls, kv_cache, max_ioc_to_compute: int) -> Self:
        self = cls(kv_cache, max_ioc_to_compute)
        first_seen_processed = await self.kv_cache.get(KV_CACHE_KEY)
        if first_seen_processed:
            logging.info(f"Retrieved {first_seen_processed} as last 'first_seen' processed")
            self.ioc_first_seen_processed_up_to = datetime.strptime(first_seen_processed, THREATFOX_DATETIME_FORMAT)
        else:  # key is not in cache
            logging.info("No last 'first_seen' found in KV cache")
            self.ioc_first_seen_processed_up_to = datetime(1970, 1, 1)
        return self

    async def compute_jarms_of_last_day_c2(self) -> int:
        """Fetch C2 of the last day on Threatfox and compute their jarm hash using jarm.online.

        Returns the number of processed iocs"""
        payload = {
            "query": "get_iocs",
            "days": 1,
        }

        threatfox_response = await pyfetch(
            THREAT_FOX_API,
            method="POST",
            body=json.dumps(payload),
        )
        threatfox_json_response = await threatfox_response.json()
        raw_first_seen_processed = None
        for ioc in threatfox_json_response["data"]:
            # TODO order by first_seen ?
            # TODO We might also skip 2 iocs having the exact same timestamp
            if ioc.get("threat_type") != C2_THREAT_TYPE:
                continue
            raw_first_seen = ioc.get("first_seen")
            first_seen = datetime.strptime(raw_first_seen, THREATFOX_DATETIME_FORMAT)
            if first_seen <= self.ioc_first_seen_processed_up_to:
                logging.debug(f"Skipping ioc {ioc['ioc']} as already processed ({raw_first_seen})")
                continue
            await self.compute_jarm_of(ioc)
            raw_first_seen_processed = raw_first_seen
            if len(self.acknowledged) == self.max_ioc_to_compute:
                break
        if raw_first_seen_processed:
            # save that we have already processed iocs up to this date
            logging.info(f"Saving {raw_first_seen_processed} as last 'first_seen' processed")
            await self.kv_cache.put(KV_CACHE_KEY, raw_first_seen_processed)
        return len(self.acknowledged)

    async def compute_jarm_of(self, ioc_details: dict):
        try:
            ioc_value: str = ioc_details["ioc"]
            if ioc_details.get("ioc_type") == IP_PORT_FORMAT:
                host, port = ioc_value.split(":", maxsplit=1)
                params = {"host": host, "port": port}
            else:
                params = {"host": ioc_value}
            if params in self.acknowledged:
                return  # We already saw this ioc

            self.acknowledged.add(params)
            url = f"{JARM_ONLINE_API}/?" + "&".join([f"{k}={v}" for k, v in params.items()])
            jarm_response = await pyfetch(url)
            json_jarm_response = await jarm_response.json()
            logging.info(f"{json_jarm_response.get('host')} - {json_jarm_response.get('jarm_hash')}")
        except Exception as e:
            logging.exception(e)
