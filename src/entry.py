import time
from js import Response
from worker import ThreatFoxJarmer


async def on_fetch(request):
    start = time.time()
    jarmer = ThreatFoxJarmer()
    processed = await jarmer.compute_jarms_of_last_day_c2()
    duration = time.time() - start
    return Response.new(f"Processed: {processed}, took {duration} seconds")
