"""Local HTTP boundary controls; not a multi-user identity system."""
import hmac
import json
import os


class RequestError(ValueError):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


def check_request(handler, write=False, authenticate=True):
    hosts = handler.headers.get_all('Host', [])
    allowed = {f'127.0.0.1:{handler.server.server_port}', f'localhost:{handler.server.server_port}'}
    if len(hosts) != 1 or hosts[0] not in allowed:
        raise RequestError(403, 'Untrusted host')
    origin = handler.headers.get('Origin')
    if origin and origin != 'http://' + hosts[0]:
        raise RequestError(403, 'Cross-origin request rejected')
    if handler.headers.get('Sec-Fetch-Site') not in (None, 'same-origin', 'none'):
        raise RequestError(403, 'Cross-site request rejected')
    if write and handler.headers.get('X-Schooldesk-Request') != '1':
        raise RequestError(403, 'Required request header missing')
    token = os.environ.get('SCHOOL_ACCESS_TOKEN')
    if token and authenticate:
        supplied = handler.headers.get('Authorization', '')
        if not hmac.compare_digest(supplied.encode(), ('Bearer ' + token).encode()):
            raise RequestError(401, 'Unlock this workspace with its access token.')


def read_json(handler, maximum=8192):
    if handler.headers.get('Transfer-Encoding'):
        raise RequestError(400, 'Transfer encoding is unsupported')
    lengths = handler.headers.get_all('Content-Length', [])
    if len(lengths) != 1 or len(lengths[0]) > 6 or not lengths[0].isascii() or not lengths[0].isdigit():
        raise RequestError(400, 'Invalid request length')
    size = int(lengths[0])
    if not 0 < size <= maximum:
        raise RequestError(413, 'Request exceeds size limit')
    if handler.headers.get_content_type() != 'application/json':
        raise RequestError(415, 'Use application/json')
    raw = handler.rfile.read(size)
    if len(raw) != size:
        raise RequestError(400, 'Incomplete request')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate key')
            result[key] = value
        return result
    try:
        def reject_constant(value):
            raise ValueError('Invalid constant')
        data = json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (ValueError, UnicodeError, RecursionError):
        raise RequestError(400, 'Invalid JSON object') from None
