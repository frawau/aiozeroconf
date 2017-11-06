#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals

""" Example of browsing for a service (in this case, HTTP) """

import asyncio
import logging
import socket
import sys

from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf


def on_service_state_change(zc, service_type, name, state_change):
    print("Service %s of type %s state changed: %s" % (name, service_type, state_change))

    if state_change is ServiceStateChange.Added:
        asyncio.ensure_future(on_service_state_change_process(zc,service_type,name))

async def on_service_state_change_process(zc,service_type, name):
    info = await zc.get_service_info(service_type, name)
    if info:
        print("  Address: %s:%d" % (socket.inet_ntoa(info.address), info.port))
        print("  Weight: %d, priority: %d" % (info.weight, info.priority))
        print("  Server: %s" % (info.server,))
        if info.properties:
            print("  Properties are:")
            for key, value in info.properties.items():
                print("    %s: %s" % (key, value))
        else:
            print("  No properties")
    else:
        print("  No info")
    print('\n')

async def do_close(zc):
    await zc.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.CRITICAL)
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ['--debug']
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    loop = asyncio.get_event_loop()
    loop.set_debug(True)

    zc=Zeroconf(loop)
    print("\nBrowsing services, press Ctrl-C to exit...\n")
    browser = ServiceBrowser(zc, "_http._tcp.local.", handlers=[on_service_state_change])
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Unregistering...")
        loop.run_until_complete(do_close(zc))
    finally:
        loop.close()
