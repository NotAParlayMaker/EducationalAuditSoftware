import sys
import os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import tempfile
import threading
import accounts
import app
from playwright.sync_api import sync_playwright, expect

with tempfile.TemporaryDirectory() as directory:
    app.DB=Path(directory)/'browser.db'
    app.initialize()
    with app.connect() as db:
        for name,role in [('admin','administrator'),('auditor','auditor'),('owner','remediation_owner'),('reviewer','reviewer')]:
            accounts.create_user(db,name,role,'fictional-browser-password')
    server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=os.environ.get('SCHOOL_TEST_CHROMIUM') or None,headless=True,args=['--no-sandbox'])
            errors=[]
            def login(name):
                page=browser.new_page()
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.goto(f'http://127.0.0.1:{server.server_port}')
                page.locator('#login-username').fill(name)
                page.locator('#login-password').fill('fictional-browser-password')
                page.get_by_role('button',name='Sign in',exact=True).click()
                expect(page.locator('#identity')).to_contain_text('Signed in as '+name)
                page.locator('nav').get_by_role('button',name='IT audits',exact=True).click()
                return page
            auditor=login('auditor')
            for key,value in {'area':'Browser audit','finding':'Fictional update evidence missing','owner':'owner','reviewer':'reviewer','due_date':'2026-12-01'}.items():
                auditor.locator('#form [name='+key+']').fill(value)
            auditor.locator('#form [name=severity]').select_option('High')
            auditor.locator('#form [name=status]').select_option('Open')
            auditor.get_by_role('button',name='Save record',exact=True).click()
            expect(auditor.locator('#message')).to_have_text('Record saved.')
            owner=login('owner')
            owner.get_by_role('button',name='Edit / transition',exact=True).click()
            owner.locator('#form [name=remediation]').fill('Inspect fictional update report')
            owner.locator('#form [name=status]').select_option('In progress')
            owner.get_by_role('button',name='Save revision',exact=True).click()
            expect(owner.locator('#message')).to_have_text('Record saved.')
            owner.get_by_role('button',name='Evidence',exact=True).click()
            owner.locator('#evidence-panel input[type=file]').set_input_files({'name':'inspection.txt','mimeType':'text/plain','buffer':b'Fictional inspection evidence'})
            owner.get_by_role('button',name='Upload evidence',exact=True).click()
            expect(owner.locator('#evidence-panel')).to_contain_text('inspection.txt')
            owner.get_by_role('button',name='Edit / transition',exact=True).click()
            owner.locator('#form [name=evidence]').fill('Attachment inspection.txt reviewed locally')
            owner.locator('#form [name=status]').select_option('Awaiting verification')
            owner.get_by_role('button',name='Save revision',exact=True).click()
            expect(owner.locator('#message')).to_have_text('Record saved.')
            reviewer=login('reviewer')
            reviewer.get_by_role('button',name='Edit / transition',exact=True).click()
            reviewer.locator('#form [name=verification]').fill('Fictional evidence independently checked')
            reviewer.locator('#form [name=closure_reason]').fill('Verified for browser test')
            reviewer.locator('#form [name=status]').select_option('Closed')
            reviewer.get_by_role('button',name='Save revision',exact=True).click()
            expect(reviewer.locator('#message')).to_have_text('Record saved.')
            reviewer.get_by_role('button',name='History',exact=True).click()
            expect(reviewer.locator('#audit-history')).to_contain_text('reviewer')
            reviewer.get_by_role('button',name='Evidence',exact=True).click()
            with reviewer.expect_download() as download:
                reviewer.get_by_role('button',name='Download',exact=True).click()
            assert download.value.suggested_filename.endswith('.txt')
            reviewer.get_by_role('button',name='Lock / clear tab',exact=True).click()
            expect(reviewer.locator('#login-form')).to_be_visible()
            assert not errors,errors
            browser.close()
            print('PASS: browser sign-in, role workflow, upload/download, verified closure, history, logout; no page errors.')
    finally:
        server.shutdown();server.server_close();thread.join()
