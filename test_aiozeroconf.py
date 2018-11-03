#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.py """


import asyncio
import logging
import socket
import struct
import time
import unittest

from threading import Event

import aiozeroconf.aiozeroconf as r
from aiozeroconf.aiozeroconf import (
    DNSHinfo,
    DNSText,
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
    ZeroconfServiceTypes,
)

import netifaces

from six import indexbytes


log = logging.getLogger('zeroconf')
original_logging_level = [None]

# On Mac OS X localhost interface is lo0
LOCALHOST = 'lo' if 'lo' in netifaces.interfaces() else 'lo0'


def setup_module():
    original_logging_level[0] = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    log.setLevel(original_logging_level[0])


class TestDunder(unittest.TestCase):

    def test_dns_text_repr(self):
        # There was an issue on Python 3 that prevented DNSText's repr
        # from working when the text was longer than 10 bytes
        text = DNSText('irrelevant', None, 0, 0, b'12345678901')
        repr(text)

        text = DNSText('irrelevant', None, 0, 0, b'123')
        repr(text)

    def test_dns_hinfo_repr_eq(self):
        hinfo = DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'os')
        assert hinfo == hinfo
        repr(hinfo)

    def test_dns_pointer_repr(self):
        pointer = r.DNSPointer(
            'irrelevant', r._TYPE_PTR, r._CLASS_IN, r._DNS_TTL, '123')
        repr(pointer)

    def test_dns_address_repr(self):
        address = r.DNSAddress('irrelevant', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        repr(address)

    def test_dns_question_repr(self):
        question = r.DNSQuestion(
            'irrelevant', r._TYPE_SRV, r._CLASS_IN | r._CLASS_UNIQUE)
        repr(question)
        assert not question != question

    def test_dns_service_repr(self):
        service = r.DNSService(
            'irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_TTL, 0, 0, 80, b'a')
        repr(service)

    def test_dns_record_abc(self):
        record = r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_TTL)
        self.assertRaises(NotImplementedError, record.__eq__, record)
        self.assertRaises(NotImplementedError, record.write, None)

    def test_service_info_dunder(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)
        info = ServiceInfo(
            type_, registration_name,
            address=socket.inet_aton("10.0.1.2"),
            port=80, weight=0, priority=0,
            server="ash-2.local.")

        assert not info != info
        repr(info)

    def test_dns_outgoing_repr(self):
        dns_outgoing = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        repr(dns_outgoing)


class PacketGeneration(unittest.TestCase):

    def test_parse_own_packet_simple(self):
        generated = r.DNSOutgoing(0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_simple_unicast(self):
        generated = r.DNSOutgoing(0, 0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_flags(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        generated.add_question(r.DNSQuestion("testname.local.", r._TYPE_SRV,
                                             r._CLASS_IN))
        r.DNSIncoming(generated.packet())

    def test_match_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        parsed = r.DNSIncoming(generated.packet())
        self.assertEqual(len(generated.questions), 1)
        self.assertEqual(len(generated.questions), len(parsed.questions))
        self.assertEqual(question, parsed.questions[0])

    def test_dns_hinfo(self):
        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(
            DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'os'))
        parsed = r.DNSIncoming(generated.packet())
        self.assertEqual(parsed.answers[0].cpu, u'cpu')
        self.assertEqual(parsed.answers[0].os, u'os')

        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(
            DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'x' * 257))
        self.assertRaises(r.NamePartTooLongException, generated.packet)


class PacketForm(unittest.TestCase):

    def test_transaction_id(self):
        """ID must be zero in a DNS-SD packet"""
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        id = indexbytes(bytes, 0) << 8 | indexbytes(bytes, 1)
        self.assertEqual(id, 0)

    def test_query_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        flags = indexbytes(bytes, 2) << 8 | indexbytes(bytes, 3)
        self.assertEqual(flags, 0x0)

    def test_response_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        flags = indexbytes(bytes, 2) << 8 | indexbytes(bytes, 3)
        self.assertEqual(flags, 0x8000)

    def test_numbers(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities,
         num_additionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(num_questions, 0)
        self.assertEqual(num_answers, 0)
        self.assertEqual(num_authorities, 0)
        self.assertEqual(num_additionals, 0)

    def test_numbers_questions(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        for i in range(10):
            generated.add_question(question)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities,
         num_additionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(num_questions, 10)
        self.assertEqual(num_answers, 0)
        self.assertEqual(num_authorities, 0)
        self.assertEqual(num_additionals, 0)


class Names(unittest.TestCase):

    def test_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("this.is.a.very.long.name.with.lots.of.parts.in.it.local.",
                                 r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 1000)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name_part(self):
        name = "%s.local." % ("a" * 1000)
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        self.assertRaises(r.NamePartTooLongException, generated.packet)

    def test_same_name(self):
        name = "paired.local."
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_lots_of_names(self):

        async def run_me(loop):
            # instantiate a zeroconf instance
            zc = Zeroconf(loop, [netifaces.AF_INET], iface=LOCALHOST)

            # create a bunch of servers
            type_ = "_my-service._tcp.local."
            name = 'a wonderful service'
            server_count = 300
            self.generate_many_hosts(zc, type_, name, server_count)

            # verify that name changing works
            self.verify_name_change(zc, type_, name, server_count)

            # we are going to monkey patch the zeroconf send to check packet sizes
            old_send = zc.send

            # needs to be a list so that we can modify it in our phony send
            longest_packet = [0, None]

            def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
                """Sends an outgoing packet."""
                packet = out.packet()
                if longest_packet[0] < len(packet):
                    longest_packet[0] = len(packet)
                    longest_packet[1] = out
                old_send(out, addr=addr, port=port)

            # monkey patch the zeroconf send
            zc.send = send

            # dummy service callback
            def on_service_state_change(zeroconf, service_type, state_change, name):
                pass

            # start a browser
            browser = ServiceBrowser(zc, type_, [on_service_state_change])

            # wait until the browse request packet has maxed out in size
            sleep_count = 0
            while sleep_count < 100 and \
                    longest_packet[0] < r._MAX_MSG_ABSOLUTE - 100:
                sleep_count += 1
                await asyncio.sleep(0.1)

            browser.cancel()
            await asyncio.sleep(0.5)

            r.log.debug('sleep_count %d, sized %d',
                        sleep_count, longest_packet[0])

            # now the browser has sent at least one request, verify the size
            assert longest_packet[0] <= r._MAX_MSG_ABSOLUTE
            assert longest_packet[0] >= r._MAX_MSG_ABSOLUTE - 100

            # mock zeroconf's logger warning() and debug()
            from mock import patch
            patch_warn = patch('zeroconf.log.warning')
            patch_debug = patch('zeroconf.log.debug')
            mocked_log_warn = patch_warn.start()
            mocked_log_debug = patch_debug.start()

            # now that we have a long packet in our possession, let's verify the
            # exception handling.
            out = longest_packet[1]
            out.data.append(b'\0' * 1000)

            # mock the zeroconf logger and check for the correct logging backoff
            call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
            # try to send an oversized packet
            zc.send(out)
            assert mocked_log_warn.call_count == call_counts[0] + 1
            assert mocked_log_debug.call_count == call_counts[0]
            zc.send(out)
            assert mocked_log_warn.call_count == call_counts[0] + 1
            assert mocked_log_debug.call_count == call_counts[0] + 1

            # force a receive of an oversized packet
            packet = out.packet()
            s = zc._respond_sockets[0]

            # mock the zeroconf logger and check for the correct logging backoff
            call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
            # force receive on oversized packet
            s.sendto(packet, 0, (r._MDNS_ADDR, r._MDNS_PORT))
            s.sendto(packet, 0, (r._MDNS_ADDR, r._MDNS_PORT))
            await asyncio.sleep(2.0)
            r.log.debug('warn %d debug %d was %s',
                        mocked_log_warn.call_count,
                        mocked_log_debug.call_count,
                        call_counts)
            assert mocked_log_debug.call_count > call_counts[0]

            # close our zeroconf which will close the sockets
            await zc.close()

            # pop the big chunk off the end of the data and send on a closed socket
            out.data.pop()
            zc._GLOBAL_DONE = False

            # mock the zeroconf logger and check for the correct logging backoff
            call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
            # send on a closed socket (force a socket error)
            zc.send(out)
            r.log.debug('warn %d debug %d was %s',
                        mocked_log_warn.call_count,
                        mocked_log_debug.call_count,
                        call_counts)
            assert mocked_log_warn.call_count > call_counts[0]
            assert mocked_log_debug.call_count > call_counts[0]
            zc.send(out)
            r.log.debug('warn %d debug %d was %s',
                        mocked_log_warn.call_count,
                        mocked_log_debug.call_count,
                        call_counts)
            assert mocked_log_debug.call_count > call_counts[0] + 2

            mocked_log_warn.stop()
            mocked_log_debug.stop()
            loop = asyncio.get_event_loop()
            loop.run_until_complete(run_me(loop))

    def verify_name_change(self, zc, type_, name, number_hosts):
        desc = {'path': '/~paulsm/'}
        info_service = ServiceInfo(
            type_, '%s.%s' % (name, type_),
            address=socket.inet_aton("10.0.1.2"),
            port=80, weight=0, priority=0, properties=desc, server="ash-2.local.")

        # verify name conflict
        self.assertRaises(
            r.NonUniqueNameException,
            zc.register_service, info_service)

        zc.register_service(info_service, allow_name_change=True)
        assert info_service.name.split('.')[0] == '%s-%d' % (
            name, number_hosts + 1)

    def generate_many_hosts(self, zc, type_, name, number_hosts):
        records_per_server = 2
        block_size = 25
        number_hosts = int(((number_hosts - 1) / block_size + 1)) * block_size
        for i in range(1, number_hosts + 1):
            next_name = name if i == 1 else '%s-%d' % (name, i)
            self.generate_host(zc, next_name, type_)
            if i % block_size == 0:
                sleep_count = 0
                while sleep_count < 40 and \
                        i * records_per_server > len(
                            zc.cache.entries_with_name(type_)):
                    sleep_count += 1
                    time.sleep(0.05)

    @staticmethod
    def generate_host(zc, host_name, type_):
        name = '.'.join((host_name, type_))
        out = r.DNSOutgoing(r._FLAGS_QR_RESPONSE | r._FLAGS_AA)
        out.add_answer_at_time(
            r.DNSPointer(type_, r._TYPE_PTR, r._CLASS_IN,
                         r._DNS_TTL, name), 0)
        out.add_answer_at_time(
            r.DNSService(type_, r._TYPE_SRV, r._CLASS_IN,
                         r._DNS_TTL, 0, 0, 80,
                         name), 0)
        zc.send(out)


class Framework(unittest.TestCase):

    def test_launch_and_close(self):
        async def run_me(rv):
            await rv.close()

        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        rv = r.Zeroconf(event_loop)
        event_loop.run_until_complete(run_me(rv))
        rv = r.Zeroconf(event_loop, [netifaces.AF_INET])
        event_loop.run_until_complete(run_me(rv))
        rv = r.Zeroconf(event_loop, [netifaces.AF_INET], iface=LOCALHOST)
        event_loop.run_until_complete(run_me(rv))
        event_loop.close()


class Exceptions(unittest.TestCase):
    browser = None
    loop = None

    @classmethod
    def setUpClass(cls):
        cls.loop = asyncio.get_event_loop()
        cls.browser = Zeroconf(cls.loop, [netifaces.AF_INET], iface=LOCALHOST)

    @classmethod
    def tearDownClass(cls):
        async def close_me(cls):
            await cls.browser.close()

        cls.loop.run_until_complete(close_me(cls))
        cls.browser = None
        cls.loop.close()
        cls.loop = None

    def test_bad_service_info_name(self):
        async def run_me(self):
            with self.assertRaises(r.BadTypeInNameException):
                await self.browser.get_service_info("type", "type_not")

        self.loop.run_until_complete(run_me(self))

    def test_bad_service_names(self):
        async def run_me(self):
            bad_names_to_try = (
                '',
                'local',
                '_tcp.local.',
                '_udp.local.',
                '._udp.local.',
                '_@._tcp.local.',
                '_A@._tcp.local.',
                '_x--x._tcp.local.',
                '_-x._udp.local.',
                '_x-._tcp.local.',
                '_22._udp.local.',
                '_2-2._tcp.local.',
                '_1234567890-abcde._udp.local.',
                '\x00._x._udp.local.',
            )
            for name in bad_names_to_try:
                with self.assertRaises(r.BadTypeInNameException):
                    await self.browser.get_service_info(name, 'x.' + name)

        self.loop.run_until_complete(run_me(self))

    def test_good_instance_names(self):
        good_names_to_try = (
            '.._x._tcp.local.',
            'x.sub._http._tcp.local.',
            '6d86f882b90facee9170ad3439d72a4d6ee9f511._zget._http._tcp.local.'
        )
        for name in good_names_to_try:
            r.service_type_name(name)

    def test_bad_types(self):
        bad_names_to_try = (
            '._x._tcp.local.',
            'a' * 64 + '._sub._http._tcp.local.',
            'a' * 62 + u'â._sub._http._tcp.local.',
        )
        for name in bad_names_to_try:
            self.assertRaises(
                r.BadTypeInNameException, r.service_type_name, name)

    def test_bad_sub_types(self):
        bad_names_to_try = (
            '_sub._http._tcp.local.',
            '._sub._http._tcp.local.',
            '\x7f._sub._http._tcp.local.',
            '\x1f._sub._http._tcp.local.',
        )
        for name in bad_names_to_try:
            self.assertRaises(
                r.BadTypeInNameException, r.service_type_name, name)

    def test_good_service_names(self):
        good_names_to_try = (
            '_x._tcp.local.',
            '_x._udp.local.',
            '_12345-67890-abc._udp.local.',
            'x._sub._http._tcp.local.',
            'a' * 63 + '._sub._http._tcp.local.',
            'a' * 61 + u'â._sub._http._tcp.local.',
        )
        for name in good_names_to_try:
            r.service_type_name(name)


class TestDnsIncoming(unittest.TestCase):

    def test_incoming_exception_handling(self):
        generated = r.DNSOutgoing(0)
        packet = generated.packet()
        packet = packet[:8] + b'deadbeef' + packet[8:]
        parsed = r.DNSIncoming(packet)
        parsed = r.DNSIncoming(packet)
        assert parsed.valid is False

    def test_incoming_unknown_type(self):
        generated = r.DNSOutgoing(0)
        answer = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        generated.add_additional_answer(answer)
        packet = generated.packet()
        parsed = r.DNSIncoming(packet)
        assert len(parsed.answers) == 0
        assert parsed.is_query() != parsed.is_response()

    def test_incoming_ipv6(self):
        # ::TODO:: could use a test here if we add IPV6 record handling
        # ie: _TYPE_AAAA
        pass


class ServiceTypesQuery(unittest.TestCase):

    @staticmethod
    async def run_me_with_listener(zeroconf_registrar):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name,
            address=socket.inet_aton("10.0.1.2"),
            address6=socket.inet_pton(socket.AF_INET6, '::1'),
            port=80,
            weight=0,
            priority=0,
            properties=desc,
            server="ash-2.local."
        )
        await zeroconf_registrar.register_service(info)

        try:
            service_types = await ZeroconfServiceTypes.find(
                zc=zeroconf_registrar, timeout=1)
            assert type_ in service_types

        finally:
            await zeroconf_registrar.close()

    def test_integration_with_listener_inet(self):
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        zeroconf_registrar = Zeroconf(event_loop, [netifaces.AF_INET], iface=LOCALHOST)
        event_loop.run_until_complete(self.run_me_with_listener(zeroconf_registrar))
        event_loop.close()

    def test_integration_with_listener_inet6(self):
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        zeroconf_registrar = Zeroconf(event_loop, [netifaces.AF_INET6])
        event_loop.run_until_complete(self.run_me_with_listener(zeroconf_registrar))
        event_loop.close()

    @staticmethod
    async def run_me_with_subtype(zeroconf_registrar):
        subtype_ = "_subtype._sub"
        type_ = "_type._tcp.local."
        name = "xxxyyy"
        # Note: discovery returns only DNS-SD type not subtype
        discovery_type = "%s.%s" % (subtype_, type_)
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            discovery_type, registration_name,
            address=socket.inet_aton("10.0.1.2"), port=80, weight=0, priority=0,
            address6=socket.inet_pton(socket.AF_INET6, '::1'),
            properties=desc, server="ash-2.local.")
        await zeroconf_registrar.register_service(info)

        try:
            service_types = await ZeroconfServiceTypes.find(
                zc=zeroconf_registrar, timeout=0.5)
            assert discovery_type in service_types

        finally:
            await zeroconf_registrar.close()

    def test_integration_with_subtype_and_listener_inet(self):
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        zeroconf_registrar = Zeroconf(event_loop, [netifaces.AF_INET], iface=LOCALHOST)
        event_loop.run_until_complete(self.run_me_with_subtype(zeroconf_registrar))
        event_loop.close()

    def test_integration_with_subtype_and_listener_inet6(self):
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        zeroconf_registrar = Zeroconf(event_loop, [netifaces.AF_INET6])
        event_loop.run_until_complete(self.run_me_with_subtype(zeroconf_registrar))
        event_loop.close()


class ListenerTest(unittest.TestCase):

    def test_integration_with_listener_class(self):

        service_added = Event()
        service_removed = Event()

        async def run_me(zcbrowser, zcregistrar):
            subtype_name = "My special Subtype"
            type_ = "_http._tcp.local."
            subtype = subtype_name + "._sub." + type_
            name = "xxxyyy"
            registration_name = "%s.%s" % (name, type_)

            class MyListener(object):
                def add_service(self, zeroconf, type, name):
                    asyncio.ensure_future(self.async_add_service(zeroconf, type, name))

                async def async_add_service(self, zeroconf, type, name):
                    await zeroconf.get_service_info(type, name)
                    service_added.set()

                def remove_service(self, zeroconf, type, name):
                    service_removed.set()

            listener = MyListener()
            zcbrowser.add_service_listener(subtype, listener=listener)

            properties = dict(
                prop_none=None,
                prop_string=b'a_prop',
                prop_float=1.0,
                prop_blank=b'a blanked string',
                prop_true=1,
                prop_false=0,
            )

            desc = {'path': '/~paulsm/'}
            desc.update(properties)
            info_service = ServiceInfo(
                subtype, registration_name,
                address=socket.inet_aton("10.0.1.2"), port=80, weight=0, priority=0,
                address6=socket.inet_pton(socket.AF_INET6, '::1'),
                properties=desc, server="ash-2.local.")
            await zcregistrar.register_service(info_service)

            try:
                await asyncio.sleep(2)
                assert service_added.is_set()

                # short pause to allow multicast timers to expire
                await asyncio.sleep(2)

                # clear the answer cache to force query
                for record in zcbrowser.cache.entries():
                    zcbrowser.cache.remove(record)

                # get service info without answer cache
                info = await zcbrowser.get_service_info(type_, registration_name)

                assert info.properties[b'prop_none'] is False
                assert info.properties[b'prop_string'] == properties['prop_string']
                assert info.properties[b'prop_float'] is False
                assert info.properties[b'prop_blank'] == properties['prop_blank']
                assert info.properties[b'prop_true'] is True
                assert info.properties[b'prop_false'] is False

                info = await zcbrowser.get_service_info(subtype, registration_name)
                assert info.properties[b'prop_none'] is False

                await zcregistrar.unregister_service(info_service)
                await asyncio.sleep(1)
                assert service_removed.is_set()
            finally:
                await zcregistrar.close()
                zcbrowser.remove_service_listener(listener)
                await zcbrowser.close()

        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        zeroconf_browser = Zeroconf(event_loop, [netifaces.AF_INET], iface=LOCALHOST)
        zeroconf_registrar = Zeroconf(event_loop, [netifaces.AF_INET], iface=LOCALHOST)
        coro = run_me(zeroconf_browser, zeroconf_registrar)
        event_loop.run_until_complete(coro)
        event_loop.close()


def test_integration():
    service_added = Event()
    service_removed = Event()

    async def run_me(loop):
        type_ = "_http._tcp.local."
        registration_name = "xxxyyy.%s" % type_

        def on_service_state_change(zeroconf, service_type, state_change, name):
            if name == registration_name:
                if state_change is ServiceStateChange.Added:
                    service_added.set()
                elif state_change is ServiceStateChange.Removed:
                    service_removed.set()

        zeroconf_browser = Zeroconf(loop, [netifaces.AF_INET], iface=LOCALHOST)
        browser = ServiceBrowser(zeroconf_browser, type_, [on_service_state_change])

        zeroconf_registrar = Zeroconf(loop, [netifaces.AF_INET], iface=LOCALHOST)
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name,
            address=socket.inet_aton("10.0.1.2"), port=80, weight=0, priority=0,
            properties=desc, server="ash-2.local.")
        zeroconf_registrar.register_service(info)

        try:
            await asyncio.sleep(1)
            assert service_added.is_set()
            # Don't remove service, allow close() to cleanup

        finally:
            await zeroconf_registrar.close()
            browser.cancel()
            await zeroconf_browser.close()
