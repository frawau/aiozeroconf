#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application is an example on how to use aiozeroconf
#
# Copyright (c) 2016 François Wautier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

import asyncio
import logging
import socket
import sys

from aiozeroconf import ServiceInfo, Zeroconf, __version__


async def test_run(r):
    print("1. Testing registration of a service...")
    desc = {'version': '0.10', 'a': 'test value', 'b': 'another value'}
    info = ServiceInfo("_http._tcp.local.",
                       "My Service Name._http._tcp.local.",
                       socket.inet_aton("127.0.0.1"), 1234, 0, 0, desc)
    print("   Registering service...")
    await r.register_service(info)
    print("   Registration done.")
    print("2. Testing query of service information...")
    print("   Getting ZOE service: %s" % (
        await r.get_service_info("_http._tcp.local.", "ZOE._http._tcp.local.")))
    print("   Query done.")
    print("3. Testing query of own service...")
    info = await r.get_service_info("_http._tcp.local.", "My Service Name._http._tcp.local.")
    assert info
    print("   Getting self: %s" % (info,))
    print("   Query done.")
    print("4. Testing unregister of service information...")
    await r.unregister_service(info)
    print("   Unregister done.")
    await r.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ['--debug']
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    # Test a few module features, including service registration, service
    # query (for Zoe), and service unregistration.
    print("Multicast DNS Service Discovery for Python, version %s" % (__version__,))
    loop = asyncio.get_event_loop()

    r = Zeroconf(loop)
    loop.run_until_complete(test_run(r))
    loop.close()
