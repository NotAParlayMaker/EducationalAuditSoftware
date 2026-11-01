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
                field=auditor.locator('#form [name='+key+']')
                if key in ('owner','reviewer'):field.select_option(value)
                else:field.fill(value)
            auditor.locator('#form [name=severity]').select_option('High')
            auditor.locator('#form [name=status]').select_option('Open')
            auditor.get_by_role('button',name='Save record',exact=True).click()
            expect(auditor.locator('#message')).to_have_text('Record saved.')
            auditor.get_by_role('button',name='Edit / transition',exact=True).click()
            auditor.locator('#form [name=finding]').fill('Unsaved change')
            auditor.get_by_role('button',name='Cancel editing',exact=True).click()
            expect(auditor.locator('#rows')).to_contain_text('Fictional update evidence missing')
            owner=login('owner')
            owner.locator('nav').get_by_role('button',name='Overview',exact=True).click()
            expect(owner.locator('#queue-items')).to_contain_text('Browser audit')
            owner.locator('#queue-items button').first.click()
            expect(owner.locator('#record-form-title')).to_contain_text('Edit finding #')
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
            reviewer.locator('#account-tools summary').click()
            reviewer.get_by_role('button',name='Show active sessions',exact=True).click()
            expect(reviewer.locator('#sessions-list')).to_contain_text('This session')
            reviewer.get_by_role('button',name='Sign out all sessions',exact=True).click()
            expect(reviewer.locator('#login-form')).to_be_visible()
            expect(reviewer.locator('#identity')).to_contain_text('All your sessions were revoked')
            admin=login('admin')
            expect(admin.locator('#operations-status')).to_contain_text('4 active accounts')
            admin.locator('#account-tools summary').click()
            admin.get_by_role('button',name='Review security events',exact=True).click()
            expect(admin.locator('#security-events')).to_contain_text('login_succeeded')
            admin.get_by_role('button',name='Check event chain',exact=True).click()
            expect(admin.locator('#security-verify-status')).to_contain_text('Chain internally consistent')
            admin.locator('#current-password').fill('fictional-browser-password')
            admin.locator('#new-password').fill('different-fictional-browser-password')
            admin.locator('#confirm-password').fill('different-fictional-browser-password')
            admin.get_by_role('button',name='Change password and sign out',exact=True).click()
            expect(admin.locator('#identity')).to_contain_text('Password changed and all sessions revoked')
            expect(admin.locator('#security-panel')).to_be_hidden()
            admin.locator('#login-username').fill('admin')
            admin.locator('#login-password').fill('different-fictional-browser-password')
            admin.get_by_role('button',name='Sign in',exact=True).click()
            expect(admin.locator('#identity')).to_contain_text('Signed in as admin')
            admin.locator('#pipeline-resource').select_option('assets')
            admin.locator('#pipeline-file').set_input_files({'name':'demo-import.csv','mimeType':'text/csv','buffer':b'tag,device,location,status\nPIPELINE-1,Laptop,Library,Available\nPIPELINE-1,Laptop,Library,Available\n'})
            admin.get_by_role('button',name='Validate and preview',exact=True).click()
            expect(admin.locator('#pipeline-status')).to_contain_text('2 valid records')
            expect(admin.locator('#pipeline-status')).to_contain_text('1 exact duplicates')
            admin.locator('#pipeline-confirm').check()
            admin.get_by_role('button',name='Import reviewed batch',exact=True).click()
            expect(admin.locator('#pipeline-status')).to_contain_text('1 inserted, 1 exact duplicates skipped')
            admin.get_by_role('button',name='Recent imports',exact=True).click()
            expect(admin.locator('#pipeline-job-list')).to_contain_text('committed')
            with admin.expect_download() as export:
                admin.get_by_role('button',name='Export first page',exact=True).click()
            import json
            payload=json.loads(Path(export.value.path()).read_text())
            assert payload['rows'][0]['tag']=='PIPELINE-1'
            admin.get_by_role('button',name='Lock / clear tab',exact=True).click()
            expect(admin.locator('#login-form')).to_be_visible()
            assert not errors,errors
            browser.close()
            print('PASS: browser sign-in, role workflow, upload/download, verified closure, history, session revocation, password change, admin events, CSV import/deduplication, JSON export, logout; no page errors.')
    finally:
        server.shutdown();server.server_close();thread.join()
