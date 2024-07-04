import json
# We can't use requests/httpx, we have to rely on JS to do HTTP requests
# See https://github.com/cloudflare/workers-sdk/issues/5608
# See https://pyodide.org/en/stable/usage/api/python-api/http.html#pyodide.http.pyfetch
from pyodide.http import pyfetch

THREAT_FOX_API = "https://threatfox-api.abuse.ch/api/v1/"
JARM_ONLINE_API = "https://jarm.online/api/v1/jarm"

MAX_IOC_TO_COMPUTE = 100

C2_THREAT_TYPE = "botnet_cc"
IP_PORT_FORMAT = "ip:port"


class IocsAcknowledged:
    def __init__(self):
        self.processed = set()

    @staticmethod
    def compute_ioc_key(ioc: dict):
        keys = []
        for k, v in sorted(ioc.items()):
            keys.append(f"{k}:{v}")
        return '-'.join(keys)

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
    def __init__(self):
        self.acknowledged = IocsAcknowledged()

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
        for ioc in threatfox_json_response["data"]:
            if ioc.get("threat_type") != C2_THREAT_TYPE:
                continue
            await self.compute_jarm_of(ioc)
            if len(self.acknowledged) == MAX_IOC_TO_COMPUTE:
                break
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
            url = f"{JARM_ONLINE_API}/?" + '&'.join([f"{k}={v}" for k, v in params.items()])
            jarm_response = await pyfetch(url)
            json_jarm_response = await jarm_response.json()
            print(f"{json_jarm_response.get('host')} - {json_jarm_response.get('jarm_hash')}")
        except Exception as e:
            print(e)


if __name__ == '__main__':
    import asyncio

    jarmer = ThreatFoxJarmer()
    processed = asyncio.run(jarmer.compute_jarms_of_last_day_c2())
    asyncio.run(jarmer.shutdown())
    print(processed)
