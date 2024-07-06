import time
from js import Response
from worker import ThreatFoxJarmer


async def on_fetch(request, env):
    start = time.time()
    kv_cache = env.threatfoxiocs
    max_ioc_to_compute = int(env.MAX_IOC_TO_COMPUTE)
    jarmer = await ThreatFoxJarmer.create(kv_cache=kv_cache, max_ioc_to_compute=max_ioc_to_compute)
    processed = await jarmer.compute_jarms_of_last_day_c2()
    duration = time.time() - start
    return Response.new(f"Processed: {processed}, took {duration} seconds")
