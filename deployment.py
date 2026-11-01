"""Explicit HTTPS gateway trust; forwarded headers never establish identity."""
import hmac
import os
import re
from urllib.parse import urlsplit

import secret_config


def cloud():return os.environ.get('SCHOOL_PROFILE','local')=='cloud'


def public_origin():
    value=os.environ.get('SCHOOL_PUBLIC_ORIGIN','')
    parsed=urlsplit(value)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment or not parsed.netloc.isascii():
        raise ValueError('Configure a valid HTTPS SCHOOL_PUBLIC_ORIGIN without a path.')
    return value.rstrip('/')


def gateway(handler):
    from security import RequestError
    if not cloud():return None
    try:
        import ipaddress
        if not ipaddress.ip_address(handler.client_address[0]).is_loopback:raise RequestError(403,'A local trusted gateway is required.')
        token=secret_config.read('SCHOOL_PROXY_TOKEN',required=True)
        if len(token)<32:raise ValueError()
        supplied=handler.headers.get('X-Schooldesk-Proxy-Token','')
        if not hmac.compare_digest(token.encode(),supplied.encode()):raise RequestError(403,'Trusted gateway required.')
        origin=public_origin()
        return urlsplit(origin).netloc,origin
    except RequestError:raise
    except (ValueError,OSError):raise RequestError(503,'Gateway configuration is unavailable.') from None


def validate():
    if os.environ.get('SCHOOL_PROFILE','local') not in ('local','cloud'):raise ValueError('SCHOOL_PROFILE must be local or cloud.')
    if os.environ.get('SCHOOL_EVIDENCE_SCAN','disabled') not in ('disabled','clamd'):raise ValueError('Unsupported evidence scanning mode.')
    if not cloud():return
    if os.environ.get('SCHOOL_AI_MODE','offline')!='offline':raise ValueError('Cloud profile requires offline AI until a reviewed de-identification workflow is available.')
    public_origin()
    if hasattr(os,'geteuid') and os.geteuid()==0:raise ValueError('The cloud request service must run as a non-root user.')
    token=secret_config.read('SCHOOL_PROXY_TOKEN',required=True)
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',token):raise ValueError('Gateway token must contain at least 32 ASCII characters.')
    secret_config.fernet('SCHOOL_MFA_KEY')
    import security_events
    if not security_events.signing_key():raise ValueError('Cloud profile requires an external SCHOOL_EVENT_KEY.')
    if os.environ.get('SCHOOL_ENCRYPTED_STORAGE_ACK')!='1':raise ValueError('Verify encrypted host and temporary storage, then set SCHOOL_ENCRYPTED_STORAGE_ACK=1. This is an operator attestation, not automatic verification.')
    if os.environ.get('SCHOOL_BACKUP_KEY') or os.environ.get('SCHOOL_BACKUP_KEY_FILE'):raise ValueError('Backup keys belong to the separate backup worker, not the application service.')
    if os.environ.get('SCHOOL_EVIDENCE_SCAN')!='clamd' or not os.environ.get('SCHOOL_CLAMD_SOCKET'):raise ValueError('Cloud profile requires a configured clamd scanner.')
