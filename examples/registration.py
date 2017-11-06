#!/usr/bin/env python3

""" Example of announcing a service (in this case, a fake HTTP server) """

import logging
import socket
import sys
import asyncio
from functools import partial

from zeroconf import ServiceInfo, Zeroconf

async def run_test(zc):
    global info, desc
    desc = {'path': '/~paulsm/'}

    info = ServiceInfo("_http._tcp.local.",
                       "Paul's Test Web Site._http._tcp.local.",
                       socket.inet_aton("127.0.0.1"), 80, 0, 0,
                       desc, "ash-2.local.")
    print("Registration of a service, press Ctrl-C to exit...")
    await zc.register_service(info)

async def do_close(zc):
    global info
    await zc.unregister_service(info)
    await zc.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ['--debug']
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    loop = asyncio.get_event_loop()

desc = {'path': '/~paulsm/'}
info = ServiceInfo("_http._tcp.local.",
                    "Paul's Test Web Site._http._tcp.local.",
                    socket.inet_aton("127.0.0.1"), 80, 0, 0,
                    desc, "ash-2.local.")
zc = Zeroconf(loop)
xx=loop.create_task(run_test(zc))
try:
    loop.run_forever()
except KeyboardInterrupt:
    print("Unregistering...")
    loop.run_until_complete(do_close(zc))
finally:
    loop.close()
