# coding=utf-8

import requests
import xml.etree.ElementTree as ET
import re
import time
from xml.sax.saxutils import escape


class E303ApiException(Exception):
    """E303 xml API exception"""
    pass


class E303:
    """Implements (the relevent parts) of the Huawei E303's xml-based API
    for sending/receiving SMS"""

    def __init__(self, api_addr):
        self.api_addr = api_addr

        self.BOX_RECEIVED = 1
        self.BOX_SENT = 2
        self.BOX_DRAFTS = 3

        self.SMS_PER_PAGE = 20
        self.TOKEN_MAX_USE = 10  # how many times max. to use one auth token
        self.TOKEN_MAX_AGE = 100000  # max. age in ms for a token

        self.cached_token = None
        self.cached_token_time = 0
        self.cached_token_usecount = 0

    def get_error(self, xml):
        """Parse an XML response for the <error> tag and return the
        error code, if possible"""
        if '<error>' in xml:
            match = re.search(r'<code>(\d*)</code>', xml)
            if match:
                return match.group(1)
            return 'unknown'
        return None

    def api_request(self, path, data=None, needs_token=True):
        """Make a request to the E303's xml api"""
        headers = {}
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
        if needs_token:
            headers['__RequestVerificationToken'] = self.get_token()

        if data:
            data = data.encode('utf-8')
            r = requests.post('http://%s/%s' % (self.api_addr, path),
                              headers=headers,
                              data=data)
        else:
            r = requests.get('http://%s/%s' % (self.api_addr, path),
                             headers=headers)

        if r.status_code != 200:
            raise E303ApiException('API returned status code %d' % r.status_code)

        err = self.get_error(r.text)
        if err:
            raise E303ApiException('API returned error code %s' % err)

        return r.content.decode('utf-8')

    def get_token(self):
        """Get an auth token from the webinterface or return a cached one,
        if it's not too old or has been used too many times"""
        now = time.time()
        if (now - self.cached_token_time > self.TOKEN_MAX_AGE or
                    self.cached_token_usecount > self.TOKEN_MAX_USE or
                    self.cached_token == None):
            xml = self.api_request('api/webserver/token', needs_token=False)

            response_regex = r'<token>(\d*)</token>'
            match = re.search(response_regex, xml)
            if not match:
                raise E303ApiException('Could not retrieve token from webinterface')

            self.cached_token = match.group(1)
            self.cached_token_usecount = 1
            self.cached_token_time = now
        else:
            self.cached_token_usecount += 1

        return self.cached_token

    def delete_sms(self, sms_id):
        data = """\
    <?xml version="1.0" encoding="UTF-8"?>
    <request>
        <Index>%s</Index>
    </request>""" % sms_id
        self.api_request('api/sms/delete-sms', data=data)

    def get_received_sms(self, callback):
        data = """\
    <?xml version="1.0" encoding="UTF-8"?>
    <request>
        <PageIndex>1</PageIndex>
        <ReadCount>%d</ReadCount>
        <BoxType>%d</BoxType>
        <SortType>0</SortType>
        <Ascending>0</Ascending>
        <UnreadPreferred>0</UnreadPreferred>
    </request>""" % (self.SMS_PER_PAGE, self.BOX_RECEIVED)

        # do this until we have no new messages
        while True:
            xml = self.api_request('api/sms/sms-list', data=data)

            root = ET.fromstring(xml)
            messages = root.findall('.//Message')
            if len(messages) < 1:
                break
            for message in messages:
                sms = (message.find('Phone').text,
                       message.find('Content').text,
                       message.find('Date').text)
                if callback(*sms):
                    if not self.delete_sms(message.find('Index').text):
                        return False
            return True

    def filter_tel(self, tel):
        """Filter a number to a format, that the e303 understands"""
        filtered = ''

        # keep leading +
        if tel[0] == '+':
            tel = tel[1:]
            filtered = '+'

        #remove everything, that isn't a digit
        filtered += ''.join(c for c in tel if c.isdigit())
        return filtered

    def send_sms(self, tel, msg):
        """Send an sms"""

        tel = self.filter_tel(tel)
        msg = escape(msg)  # special chars need to be xml encoded (&amp; etc.)

        data = """\
    <?xml version="1.0" encoding="UTF-8"?>
    <request>
        <Index>-1</Index>
        <Phones>
            <Phone>%s</Phone>
        </Phones>
        <Sca/>
        <Content>%s</Content>
        <Length>%d</Length>
        <Reserved>1</Reserved>
        <Date>%s</Date>
    </request>""" % (tel, msg, len(msg), '1844-10-22 00:00:01')  # the date literally doesn't matter
        self.api_request('api/sms/send-sms', data=data)

    def delete_box(self, box):
        """Delete all sent sms in a given box from the device"""
        data = """\
    <?xml version="1.0" encoding="UTF-8"?>
    <request>
        <PageIndex>1</PageIndex>
        <ReadCount>%d</ReadCount>
        <BoxType>%d</BoxType>
        <SortType>0</SortType>
        <Ascending>0</Ascending>
        <UnreadPreferred>0</UnreadPreferred>
    </request>""" % (self.SMS_PER_PAGE, box)

        # do this until we have no new messages
        while True:
            xml = self.api_request('api/sms/sms-list', data=data)

            root = ET.fromstring(xml)
            indices = root.findall('.//Index')
            if len(indices) < 1:
                break
            for ind in indices:
                self.delete_sms(ind.text)
        return True

    def delete_sent(self):
        return self.delete_box(self.BOX_SENT)

    def delete_drafts(self):
        return self.delete_box(self.BOX_DRAFTS)

    def get_info(self):
        """Get IMEI, IMSI, phone number, etc. of the E303 device"""
        xml = self.api_request('api/device/information')

        root = ET.fromstring(xml)
        return {
            'tel': root.findtext('.//Msisdn'),
            'imei': root.findtext('.//Imei'),
            'imsi': root.findtext('.//Imsi'),
            'serial': root.findtext('.//SerialNumber')}
