# python non-English perfmon counter test
# -*- coding: latin-1 -*-
#
# change k_hostname to a specific hostname

import os
import sys
import re
import logging
from requests import Session
import kerberos
import httplib
import base64
import shlex
from cStringIO import StringIO
import constants as c
from xml.etree import ElementTree as ET

#############################################################################
# This is a test for querying non-English perfmon counters
# You must kinit before running
#  Change hostname here
k_hostname = 'hostname'
#############################################################################


challenge = ''
query = 'Select Caption, DeviceID, Name From Win32_Processor'
_CONTENT_TYPE = {'Content-Type': 'application/soap+xml;charset=UTF-8'}
request_template_name = 'enumerate'
_REQUEST_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'request')
_XML_WHITESPACE_PATTERN = re.compile(r'>\s+<')
WMICIMV2 = 'http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2'
DEFAULT_RESOURCE_URI = '{0}/*'.format(WMICIMV2)
_ENCRYPTED_CONTENT_TYPE = {"Content-Type": "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"Encrypted Boundary\""}
_BODY = """--Encrypted Boundary
Content-Type: application/HTTP-Kerberos-session-encrypted
OriginalContent: type=application/soap+xml;charset=UTF-8;Length={original_length}
--Encrypted Boundary
Content-Type: application/octet-stream
{emsg}--Encrypted Boundary
"""


s = Session()

# main script
gssflags = kerberos.GSS_C_CONF_FLAG | kerberos.GSS_C_MUTUAL_FLAG | kerberos.GSS_C_SEQUENCE_FLAG | kerberos.GSS_C_INTEG_FLAG
result_code, context = kerberos.authGSSClientInit('HTTP@{0}'.format(k_hostname), gssflags=gssflags)
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

kind, challenge = resp.headers['www-authenticate'].strip().split(' ', 1)
rc = kerberos.authGSSClientStep(context, challenge)
if rc == kerberos.AUTH_GSS_COMPLETE:
    print("Authenticated {0}".format(kerberos.authGSSClientUserName(context)))


def _build_ps_command_line_elem(command_line):
    prefix = "rsp"
    ET.register_namespace(prefix, c.XML_NS_MSRSP)
    command_line_elem = ET.Element('{%s}CommandLine' % c.XML_NS_MSRSP)
    command_elem = ET.Element('{%s}Command' % c.XML_NS_MSRSP)
    command_elem.text = 'powershell'
    command_line_elem.append(command_elem)
    arguments_elem = ET.Element('{%s}Arguments' % c.XML_NS_MSRSP)
    arguments_elem.text = '-command'
    command_line_elem.append(arguments_elem)
    arguments_elem = ET.Element('{%s}Arguments' % c.XML_NS_MSRSP)
    arguments_elem.text = command_line
    command_line_elem.append(arguments_elem)
    tree = ET.ElementTree(command_line_elem)
    str_io = StringIO()
    tree.write(str_io, encoding="utf-8")
    return str_io.getvalue()    


def _build_command_line_elem(command_line):
    command_line_parts = shlex.split(command_line, posix=False)
    prefix = "rsp"
    ET.register_namespace(prefix, c.XML_NS_MSRSP)
    command_line_elem = ET.Element('{%s}CommandLine' % c.XML_NS_MSRSP)
    command_elem = ET.Element('{%s}Command' % c.XML_NS_MSRSP)
    command_elem.text = command_line_parts[0]
    command_line_elem.append(command_elem)
    for arguments_text in command_line_parts[1:]:
        arguments_elem = ET.Element('{%s}Arguments' % c.XML_NS_MSRSP)
        arguments_elem.text = arguments_text
        command_line_elem.append(arguments_elem)
    tree = ET.ElementTree(command_line_elem)
    str_io = StringIO()
    tree.write(str_io, encoding="utf-8")
    return str_io.getvalue()


def _find_shell_id(elem):
    xpath = './/{%s}Selector[@Name="ShellId"]' % c.XML_NS_WS_MAN
    return elem.findtext(xpath).strip()


def _find_command_id(elem):
    xpath = './/{%s}CommandId' % c.XML_NS_MSRSP
    return elem.findtext(xpath).strip()


def _find_stream(elem, command_id, stream_name):
    xpath = './/{%s}Stream[@Name="%s"][@CommandId="%s"]' \
        % (c.XML_NS_MSRSP, stream_name, command_id)
    for elem in elem.findall(xpath):
        if elem.text is not None:
            yield base64.decodestring(elem.text)


def _stripped_lines(stream_parts):
    results = []
    for line in ''.join(stream_parts).splitlines():
        if line.strip():
            results.append(line.strip())
    return results


def _find_exit_code(elem, command_id):
    command_state_xpath = './/{%s}CommandState[@CommandId="%s"]' \
        % (c.XML_NS_MSRSP, command_id)
    command_state_elem = elem.find(command_state_xpath)
    if command_state_elem is not None:
        exit_code_xpath = './/{%s}ExitCode' % c.XML_NS_MSRSP
        exit_code_text = command_state_elem.findtext(exit_code_xpath)
        return None if exit_code_text is None else int(exit_code_text)


def send_request(request_template_name, **kwargs):
    # load request template and create payload
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '{}.xml'.format(request_template_name))
    with open(path) as f:
        request_template = _XML_WHITESPACE_PATTERN.sub('><', f.read()).strip()

    payload = request_template.format(**kwargs)
    orig_len = len(payload)
    ereq = base64.b64encode(payload)
    rc, pad_len = kerberos.authGSSClientWrapIov(context, ereq, 1)
    ewrap = kerberos.authGSSClientResponse(context)
    wrapped_req = bytes(base64.b64decode(ewrap))
    body = _BODY.replace('\n', '\r\n')
    body = bytes(body.format(original_length=orig_len + pad_len, emsg=wrapped_req))
    resp = s.request('POST', url, headers=k_headers, data=body)
    if resp.status_code == httplib.FORBIDDEN:
        logging.error(
            "Forbidden: Check WinRM port and version")
    elif resp.status_code == httplib.UNAUTHORIZED:
        logging.error(
            "Unauthorized: Check username and password")
    elif resp.status_code == httplib.OK:
        logging.debug("HTTP OK!  Query Sent")
        print("HTTP OK!  Query Sent")
        b_start = resp.content.index("Content-Type: application/octet-stream") + \
            len("Content-Type: application/octet-stream\r\n")
        b_end = resp.content.index("--Encrypted Boundary", b_start)
        ebody = base64.b64encode(resp.content[b_start:b_end])
        rc = kerberos.authGSSClientUnwrapIov(context, ebody)
        if rc == kerberos.AUTH_GSS_COMPLETE:
            body = base64.b64decode(kerberos.authGSSClientResponse(context))
        import pdb; pdb.set_trace()
        return ET.fromstring(body)
    else:
        logging.debug("HTTP status: {0}, {1}".format(
            resp.status_code, resp.content))
    return None


# create shell
elem = send_request('create')
if not elem:
    sys.exit(0)
shell_id = _find_shell_id(elem)
print 'shell_id: {}'.format(shell_id)
# run command
ctrs = ["\Processeur(*)\% d’inactivité", "\Processeur(*)\% temps privilégié", "\Processeur(*)\% temps DPC"]

command_line = "\"& {{get-counter -counter @({0})}}\" ".format(','.join('(\\"{}\\")'.format(counter) for counter in ctrs))
# command_line_elem = """<rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:Command>powershell</rsp:Command><rsp:Arguments>-command</rsp:Arguments><rsp:Arguments>"&amp; {get-counter -counter @((\\\"\Processeur(*)\% d’inactivité\\\"))}"</rsp:Arguments></rsp:CommandLine>"""
# - send command
command_line_elem = _build_ps_command_line_elem(command_line)
print command_line_elem
# import pdb; pdb.set_trace()
# command_line_elem = """<rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:Command>powershell</rsp:Command><rsp:Arguments>-command</rsp:Arguments><rsp:Arguments>"&amp; {get-counter \\"\Processeur(*)\% d’inactivité\\"}"</rsp:Arguments></rsp:CommandLine>"""
# print command_line_elem
command_elem = send_request(
    'command', shell_id=shell_id, command_line_elem=command_line_elem,
    timeout=60)
# - get command id
command_id = _find_command_id(command_elem)
# - receive results
stdout_parts = []
stderr_parts = []
for i in xrange(9999):
    receive_elem = send_request(
        'receive', shell_id=shell_id, command_id=command_id)
    stdout_parts.extend(
        _find_stream(receive_elem, command_id, 'stdout'))
    stderr_parts.extend(
        _find_stream(receive_elem, command_id, 'stderr'))
    exit_code = _find_exit_code(receive_elem, command_id)
    if exit_code is not None:
        break
else:
    raise Exception("Reached max requests per command.")
stdout = _stripped_lines(stdout_parts)
stderr = _stripped_lines(stderr_parts)
# - terminate signal
send_request('signal',
             shell_id=shell_id,
             command_id=command_id,
             signal_code=c.SHELL_SIGNAL_TERMINATE)
# delete shell
send_request('delete', shell_id=shell_id)
# close connection
s.close()
kerberos.authGSSClientClean(context)

sout = '\n'.join(stdout)
print sout
print stdout
print '\n'.join(stderr)
