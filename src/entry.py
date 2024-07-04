"""
This does NOT work as cloudflare worker do not support packages yet,
see: https://github.com/cloudflare/workers-sdk/issues/5608
"""

import time

from js import Response
from worker import ThreatFoxJarmer


async def on_fetch(request):
    start = time.time()
    jarmer = ThreatFoxJarmer()
    processed = await jarmer.compute_jarms_of_last_day_c2()
    await jarmer.shutdown()
    duration = time.time() - start
    return Response.new(f"Processed: {processed}, took {duration} seconds")
