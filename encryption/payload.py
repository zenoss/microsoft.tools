# python kerberos encrypted payload test
# kinit outside of test
#
# change k_hostname to a specific hostname

import os
import re
import logging
from requests import Session,Request
import kerberos
import httplib
import base64
import xml.dom.minidom
from curses.ascii import isprint

challenge = ''
query = 'Select Caption, DeviceID, Name From Win32_Processor'
_CONTENT_TYPE = {'Content-Type': 'application/soap+xml;charset=UTF-8'}
request_template_name = 'enumerate'
_REQUEST_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'request')
_XML_WHITESPACE_PATTERN = re.compile(r'>\s+<')
WMICIMV2 = 'http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2'
DEFAULT_RESOURCE_URI = '{0}/*'.format(WMICIMV2)
################################################
#  Change hostname here
k_hostname = 'win2008mem.solad.loc'
###############################################
_ENCRYPTED_CONTENT_TYPE={"Content-Type" : "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"Encrypted Boundary\""}
_BODY="""--Encrypted Boundary
Content-Type: application/HTTP-Kerberos-session-encrypted
OriginalContent: type=application/soap+xml;charset=UTF-8;Length={original_length}
--Encrypted Boundary
Content-Type: application/octet-stream
{emsg}--Encrypted Boundary
"""


s = Session()

# main script
gssflags = kerberos.GSS_C_CONF_FLAG|kerberos.GSS_C_MUTUAL_FLAG|kerberos.GSS_C_SEQUENCE_FLAG|kerberos.GSS_C_INTEG_FLAG
result_code, context = kerberos.authGSSClientInit('HTTP@{0}'.format(k_hostname),gssflags=gssflags)
if result_code != kerberos.AUTH_GSS_COMPLETE:
    logging.error('kerberos authGSSClientInit failed')

logging.debug('GSSAPI step challenge="{0}"'.format(challenge))
rc = kerberos.AUTH_GSS_CONTINUE
rc = kerberos.authGSSClientStep(context, challenge)

base64_client_data = kerberos.authGSSClientResponse(context)

# set up headers
url = "http://{k_hostname}:5985/wsman".format(k_hostname=k_hostname)
k_headers = _ENCRYPTED_CONTENT_TYPE

kerbkey = 'Kerberos {0}'.format(base64_client_data)

i_headers = _CONTENT_TYPE
i_headers['Authorization'] = kerbkey
s.headers.update({'Accept-Encoding': '*'})
resp = s.request('POST', url, headers=i_headers)

kind, challenge = resp.headers['www-authenticate'].strip().split(' ',1)
rc = kerberos.authGSSClientStep(context,challenge)
if rc == kerberos.AUTH_GSS_COMPLETE:
    print("Authenticated {0}".format(kerberos.authGSSClientUserName(context)))

# load request template and create payload
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'enumerate.xml')
with open(path) as f:
    request_template = _XML_WHITESPACE_PATTERN.sub('><', f.read()).strip()

payload = request_template.format(resource_uri=DEFAULT_RESOURCE_URI,wql=query)
payload_xml = xml.dom.minidom.parseString(payload)
pretty_xml_as_string = payload_xml.toprettyxml(indent="  ")
print("Enumeration payload before encryption:\n{0}".format(pretty_xml_as_string))
req = bytes(payload)

orig_len = len(payload)
ereq = base64.b64encode(payload)
rc,pad_len = kerberos.authGSSClientWrapIov(context,ereq,1)
ewrap = kerberos.authGSSClientResponse(context)
wrapped_req = bytes(base64.b64decode(ewrap))
body = _BODY.replace('\n','\r\n')
body = bytes(body.format(original_length=orig_len+pad_len,emsg=wrapped_req))
print_body = ''.join([i if isprint(i) else '.' for i in body])
print("Enumeration payload after encryption:\n{0}".format(print_body))

resp = s.request('POST', url, headers=k_headers,data=body)
if resp.status_code == httplib.FORBIDDEN:
    logging.error(
        "Forbidden: Check WinRM port and version")
elif resp.status_code == httplib.UNAUTHORIZED:
    logging.error(
        "Unauthorized: Check username and password")
elif resp.status_code == httplib.OK:
    logging.debug("HTTP OK!  Query Sent")
    print("HTTP OK!  Query Sent")
    print_body = ''.join([i if isprint(i) else '.' for i in resp.content])
    print("Response from server:\n{0}".format(print_body))
    b_start = resp.content.index("Content-Type: application/octet-stream") + \
              len("Content-Type: application/octet-stream\r\n")
    b_end = resp.content.index("--Encrypted Boundary",b_start)
    ebody = base64.b64encode(resp.content[b_start:b_end])
    rc = kerberos.authGSSClientUnwrapIov(context, ebody)
    if rc == kerberos.AUTH_GSS_COMPLETE:
        body = base64.b64decode(kerberos.authGSSClientResponse(context))
        body_xml = xml.dom.minidom.parseString(body)
        pretty_xml_as_string = body_xml.toprettyxml(indent="  ")
        print("{0}".format(pretty_xml_as_string))
else:
    logging.debug("HTTP status: {0}, {1}".format(
        resp.status_code,resp.content))


s.close()
kerberos.authGSSClientClean(context)

