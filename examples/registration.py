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

""" Example of announcing a service (in this case, a fake HTTP server) """

import asyncio
import logging
import socket
import sys

from aiozeroconf import ServiceInfo, Zeroconf


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
xx = loop.create_task(run_test(zc))
try:
    loop.run_forever()
except KeyboardInterrupt:
    print("Unregistering...")
    loop.run_until_complete(do_close(zc))
finally:
    loop.close()
