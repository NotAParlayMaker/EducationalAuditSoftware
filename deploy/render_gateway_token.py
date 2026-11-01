"""Generate a private nginx header include from an explicitly configured token."""
import os
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import secret_config


def main():
    if len(sys.argv)!=2:raise SystemExit('Usage: render_gateway_token.py NEW_INCLUDE_PATH')
    token=secret_config.read('SCHOOL_PROXY_TOKEN',required=True)
    if not re.fullmatch('[A-Za-z0-9_-]{32,128}',token):raise SystemExit('Invalid gateway token format.')
    descriptor=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(descriptor,'w') as output:output.write('proxy_set_header X-Schooldesk-Proxy-Token "'+token+'";\n')
    print('Private gateway include created; token was not printed.')


if __name__=='__main__':main()
