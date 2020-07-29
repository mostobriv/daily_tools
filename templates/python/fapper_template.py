import asyncio
import aiohttp
import sys


QUEUE_MAXSIZE   = 80
WORKERS_TOTAL   = QUEUE_MAXSIZE // 4

URL = "YOUR_URL"

async def fap(val):
    global URL

    h = {'YOUR': 'HEADERS'}

    while True:
        try:
            async with aiohttp.ClientSession() as session:
                res = await session.post(URL, headers=h, json={'key': val})
                restext = await res.text()
                print(restext)
        except Exception as e:
            continue

    return


def main(argc, argv):
    global QUEUE_MAXSIZE, WORKERS_TOTAL

    loop = asyncio.get_event_loop()
    queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
    feeder_is_alive = True



    async def feeder(name, q):
        nonlocal feeder_is_alive

        for i in range(1337):
            try:
                for j in range(5):
                    await q.put((i,))
            except Exception as e:
                print("[!] Exception: %s in %s, with %s" % (e, name, i))

        feeder_is_alive = False
        await q.join()


    async def worker(name, handle, q):
        nonlocal feeder_is_alive

        while feeder_is_alive or not q.empty():
            args = await q.get()
            try:
                await handle(*args)
            except Exception as e:
                print("[!] Exception: %s in %s, with %s" % (e, name, args) )
            finally:
                q.task_done()
                

    worker_pool = [worker('fapper_worker_%d' % i, fap, queue) for i in range(WORKERS_TOTAL)]
    task = asyncio.wait([feeder('batya_fapper', queue), *worker_pool], loop=loop)
    loop.run_until_complete(task)


if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))
