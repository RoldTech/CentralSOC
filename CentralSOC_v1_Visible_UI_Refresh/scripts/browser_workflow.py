"""Opt-in real-browser smoke test against an isolated temporary database.
Install playwright and its chromium browser, then run this script from project root.
Never connects to an existing database or enables AI calls.
"""
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    with tempfile.TemporaryDirectory(prefix='centralsoc-browser-') as tmp:
        os.environ.update(REGEXSOC_ENV='development', REGEXSOC_SECRET_KEY=secrets.token_hex(32),
                          REGEXSOC_UPLOAD_DIR=tmp+'/uploads', REGEXSOC_RULE_STATE=tmp+'/rules.json',
                          CENTRALSOC_AI_ENABLED='0')
        from regexsoc.web import create_app
        from regexsoc.db.auth_service import create_user
        from regexsoc.db.session import session_scope
        app=create_app('sqlite:///'+tmp+'/browser.db')
        password=secrets.token_urlsafe(24)+'-Aa1!'
        with session_scope(app.extensions['regexsoc_engine']) as db:
            create_user(db,'browser-admin',password,'ADMIN')
        server=make_server('127.0.0.1',0,app)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        base=f'http://127.0.0.1:{server.server_port}'
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch()
                page=browser.new_page(viewport={'width':1440,'height':1000})
                page.goto(base+'/login');page.get_by_label('Username',exact=True).fill('browser-admin')
                page.get_by_label('Password',exact=True).fill(password);page.get_by_role('button',name='Sign in',exact=True).click()
                page.goto(base+'/log-analysis');page.locator('#log-file').set_input_files(str(Path(__file__).resolve().parents[1]/'sample_logs/ssh_auth.log'))
                page.get_by_role('button',name='Analyze selected files').click()
                page.goto(base+'/alerts');page.get_by_role('link',name='Investigate',exact=True).first.click()
                page.locator('#verdict').select_option('TRUE_POSITIVE');page.locator('#verdict-reason').fill('Browser test reviewed supporting authentication evidence')
                page.locator('form.verdict-form button').click()
                page.get_by_role('link',name='Investigation assistant',exact=True).click()
                page.get_by_role('button',name='Build local evidence brief').click()
                expect(page.get_by_text('Run #1 · LOCAL · COMPLETED',exact=True)).to_be_visible()
                page.goto(base+'/security-memory');expect(page.get_by_text('TRUE_POSITIVE',exact=True)).to_be_visible()
                page.goto(base+'/incidents');page.locator('#title').fill('Browser response case')
                page.get_by_role('button',name='Create incident',exact=True).click()
                page.get_by_role('link',name='Response orchestration',exact=True).click()
                page.locator('#reason').fill('Preserve metadata for the browser workflow test')
                page.get_by_role('button',name='Request snapshot',exact=True).click()
                page.get_by_role('button',name='Approve',exact=True).click()
                page.get_by_role('button',name='Execute local snapshot',exact=True).click()
                expect(page.get_by_text('Run #1 · COMPLETED',exact=True)).to_be_visible()
                page.goto(base+'/alerts');Path('test-results').mkdir(exist_ok=True)
                page.screenshot(path='test-results/triage-desktop.png',full_page=True)
                page.set_viewport_size({'width':390,'height':844});page.screenshot(path='test-results/triage-mobile.png',full_page=True)
                browser.close()
            print('Browser workflow passed. Screenshots: test-results/')
        finally:
            server.shutdown();worker.join();app.extensions['regexsoc_engine'].dispose()

if __name__=='__main__':main()
