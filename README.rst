python-aiozeroconf
===============

.. image:: https://travis-ci.com/frawau/aiozeroconf.svg?branch=master
    :target: https://travis-ci.com/frawau/aiozeroconf


This is port of  pyzeroconf to asyncio. It is based on pyzeroconf,
Multicast DNS Service Discovery for Python, originally by Paul Scott-Murphy
(https://github.com/paulsm/pyzeroconf), modified by William McBrine (https://github.com/wmcbrine/pyzeroconf).
This port was written by François Wautier (https://github.com/frawau/pyzeroconf).

The original William McBrine's fork note::

    This fork is used in all of my TiVo-related projects: HME for Python
    (and therefore HME/VLC), Network Remote, Remote Proxy, and pyTivo.
    Before this, I was tracking the changes for zeroconf.py in three
    separate repos. I figured I should have an authoritative source.

    Although I make changes based on my experience with TiVos, I expect that
    they're generally applicable. This version also includes patches found
    on the now-defunct (?) Launchpad repo of pyzeroconf, and elsewhere
    around the net -- not always well-documented, sorry.

Compatible with:

* Bonjour
* Avahi

Compared to some other Zeroconf/Bonjour/Avahi Python packages, python-zeroconf:

* isn't tied to Bonjour or Avahi
* doesn't use D-Bus
* is pip-installable

Python compatibility
--------------------

* CPython 3.5+

Versioning
----------

This project's versions follow the following pattern: MAJOR.MINOR.PATCH.

* MAJOR version has been 0 so far
* MINOR version is incremented on backward incompatible changes
* PATCH version is incremented on backward compatible changes

Status
------

It is the very beginning. I plan to use this in a project.

Compare to the original package, a number of method have become coroutines.


How to get python-zeroconf?
===========================

* PyPI page https://pypi.python.org/pypi/zeroconf
* GitHub project https://github.com/jstasiak/python-zeroconf

The easiest way to install python-zeroconf is using pip::

    pip3 install zeroconf



How do I use it?
================

Here's an example of browsing for a service:

.. code-block:: python

    import asyncio
    from aiozeroconf import ServiceBrowser, Zeroconf

    async def do_close(zc):
        await zc.close()

    class MyListener(object):

        def remove_service(self, zeroconf, type_, name):
            print("Service %s removed" % (name,))

        def add_service(self, zeroconf, type_, name):
            asyncio.ensure_future(self.found_service(zeroconf, type_, name))

        async def found_service(self, zeroconf, type_, name):
            info = await zeroconf.get_service_info(type_, name)
            print("Adding {}".format(info))

    loop = asyncio.get_event_loop()
    zeroconf = Zeroconf(loop)
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Unregistering...")
        loop.run_until_complete(do_close(zeroconf))
    finally:
        loop.close()


.. note::

    Discovery and service registration use *all* available network interfaces by default
    and both IPv4 and IPv6. If you want to customize that you need to specify:
        ``address_family``: a list containing netifaces.AF_NET and/or netiface.AF_INET6

        ``iface``: the name of the interface (e.g. "lo", "eth0")
    when constructing ``Zeroconf`` object (see the code for details).

If you don't know the name of the service you need to browse for, try:

.. code-block:: python

    import asyncio
    from aiozeroconf import Zeroconf, ZeroconfServiceTypes

    async def list_service(zc):
        los = await ZeroconfServiceTypes.find(zc,timeout=0.5)
        print ("Found {}".format(los))

    loop = asyncio.get_event_loop()
    zc = Zeroconf(loop)
    loop.run_until_complete(list_service(zc))
    loop.close()


See examples directory for more.

You can also run the module with::

    python3 -m aiozeroconf

Try -h for help

Changelog
=========

0.1.0
----

^ First version
* Not all unit test work yet


License
=======

GPL, see COPYING file for details.
