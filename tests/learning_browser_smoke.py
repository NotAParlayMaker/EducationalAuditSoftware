"""Actual-browser learning workflow with isolated fictional accounts and records."""
import sys
import os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from datetime import datetime,timedelta,timezone
import tempfile
import threading

from playwright.sync_api import sync_playwright,expect
import accounts
import app


with tempfile.TemporaryDirectory() as folder:
    app.DB=Path(folder)/'learning.db';app.initialize()
    with app.connect() as db:
        for name,role in [('admin','administrator'),('registrar','registrar'),('teacher-one','teacher'),('teacher-two','teacher')]:
            accounts.create_user(db,name,role,'fictional-browser-password')
    server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=os.environ.get('SCHOOL_TEST_CHROMIUM') or None,headless=True,args=['--no-sandbox'])
            errors=[]
            def login(name):
                page=browser.new_page();page.on('pageerror',lambda error:errors.append(str(error)))
                page.goto(f'http://127.0.0.1:{server.server_port}')
                page.locator('#login-username').fill(name);page.locator('#login-password').fill('fictional-browser-password')
                page.get_by_role('button',name='Sign in',exact=True).click();expect(page.locator('#identity')).to_contain_text('Signed in as '+name)
                return page
            registrar=login('registrar');registrar.locator('nav').get_by_role('button',name='Students',exact=True).click()
            for key,value in {'name':'Fictional learner','year':'8','guardian':'Private fictional guardian'}.items():registrar.locator('#form [name='+key+']').fill(value)
            registrar.get_by_role('button',name='Save record',exact=True).click();expect(registrar.locator('#message')).to_have_text('Record saved.')
            registrar.locator('#learning-nav').click()
            registrar.locator('#learning-class-form [name=name]').fill('Ecology class')
            registrar.locator('#learning-class-form [name=teacher]').select_option('teacher-one')
            registrar.locator('#learning-class-form button').click();expect(registrar.locator('#learning-status')).to_have_text('Saved.')
            registrar.locator('#learning-student-search [name=search]').fill('Fictional learner');registrar.locator('#learning-student-search button').click()
            expect(registrar.locator('#learning-enrollment-form option')).to_have_count(1)
            registrar.locator('#learning-enrollment-form [name=student_id]').select_option(index=0);registrar.locator('#learning-enrollment-form button').click()
            expect(registrar.get_by_role('button',name='Open evidence',exact=True)).to_have_count(1)
            teacher=login('teacher-one');expect(teacher.locator('#learning-panel')).to_be_visible()
            expect(teacher.locator('nav').get_by_role('button',name='Students',exact=True)).to_be_hidden()
            for key,value in {'code':'food-web','title':'Food-web reasoning','rubric_version':'1','criteria':'Explain a causal chain and justify a prediction.'}.items():teacher.locator('#learning-skill-form [name='+key+']').fill(value)
            teacher.locator('#learning-skill-form button').click();expect(teacher.locator('#learning-status')).to_have_text('Saved.')
            teacher.get_by_role('button',name='Open evidence',exact=True).click();expect(teacher.locator('#learning-student-detail')).to_contain_text('No teacher review')
            today=datetime.now(timezone.utc).date();yesterday=today-timedelta(days=1)
            def observe(method,outcome,day,context,note):
                f=teacher.locator('#learning-observation-form');f.locator('[name=skill_id]').select_option(index=0)
                f.locator('[name=observed_on]').fill(day.isoformat());f.locator('[name=method]').select_option(method);f.locator('[name=outcome]').select_option(outcome)
                f.locator('[name=context]').fill(context);f.locator('[name=observation]').fill(note);f.locator('button').click()
                expect(teacher.locator('#learning-status')).to_have_text('Saved.');expect(teacher.locator('#learning-student-detail')).to_contain_text(note)
            observe('written','demonstrated',yesterday,'Forest scenario','<script>window.learningUnsafe=true</script> Fictional written reasoning.')
            observe('transfer','demonstrated',today,'Pond scenario','Explained unfamiliar pond evidence.')
            observe('oral','inaccessible',today,'Audio task unavailable','An accessible alternative is needed.')
            review=teacher.locator('#learning-review-form');review.locator('[name=skill_id]').select_option(index=0)
            review.locator('[name=judgment]').select_option('demonstrated_across_contexts');review.locator('[name=rationale]').fill('Two contexts and formats support this provisional formative judgment.')
            expect(review.locator('input[name=evidence_id]')).to_have_count(2)
            for checkbox in review.locator('input[name=evidence_id]').all():checkbox.check()
            review.locator('input[type=checkbox]').last.check();review.locator('button').click()
            expect(teacher.locator('#learning-status')).to_have_text('Saved.');expect(teacher.locator('#learning-student-detail')).to_contain_text('demonstrated across contexts')
            request=teacher.locator('#learning-request-form');request.locator('[name=skill_id]').select_option(index=0);request.locator('[name=reported_source]').select_option('student')
            request.locator('[name=reason]').fill('Offer an accessible oral opportunity.');request.locator('[name=student_statement]').fill('I would like to explain the reasoning orally.');request.locator('button').click()
            expect(teacher.locator('[id^=learning-resolve-]')).to_have_count(1)
            observe('oral','demonstrated',today,'Accessible discussion','Explained the chain in an accessible discussion.')
            resolution=teacher.locator('[id^=learning-resolve-]');resolution.locator('[name=resolution]').fill('Accessible discussion completed; evidence retained for review.')
            resolution.locator('[name=observation_id]').select_option(index=1);resolution.locator('button').click()
            expect(teacher.locator('#learning-status')).to_have_text('Saved.');expect(teacher.locator('[id^=learning-resolve-]')).to_have_count(0)
            expect(teacher.locator('#learning-timeline')).to_contain_text('reassessment resolved')
            expect(teacher.locator('#learning-student-detail')).to_contain_text('evidence changed since review')
            assert teacher.evaluate('window.learningUnsafe') is None
            other=login('teacher-two');expect(other.locator('#learning-panel')).to_contain_text('No classes are currently assigned to you.')
            expect(other.locator('#learning-panel')).not_to_contain_text('Fictional learner')
            registrar.locator('#learning-assignment-form [name=teacher]').select_option('teacher-two');registrar.locator('#learning-assignment-form button').click()
            expect(registrar.locator('#learning-status')).to_have_text('Saved.')
            teacher.locator('#learning-nav').click();expect(teacher.locator('#learning-panel')).to_contain_text('No classes are currently assigned to you.')
            expect(teacher.locator('#learning-panel')).not_to_contain_text('Fictional learner')
            teacher.locator('#lock-workspace').click();expect(teacher.locator('#learning-panel')).to_be_hidden()
            assert not errors,errors
            browser.close()
            print('PASS: registrar enrollment, assigned-teacher evidence, missing opportunities, cited review, reassessment resolution, safe text rendering, transfer revocation and logout; no page errors.')
    finally:server.shutdown();server.server_close();thread.join(timeout=3)
