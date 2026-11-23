"""Optional browser acceptance checks. Requires playwright + Chromium (dev only)."""
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parent.parent
with sync_playwright() as p:
 b=p.chromium.launch(headless=True,args=['--no-sandbox'])
 page=b.new_page(viewport={'width':1440,'height':1050});errs=[];page.on('pageerror',lambda e:errs.append(str(e)))
 page.goto('http://127.0.0.1:8788');page.wait_for_timeout(2600)
 print('interfaces',page.locator('#capture-iface').inner_text())
 page.screenshot(path=str(ROOT/'release/screenshots/workspace.png'),full_page=True)
 page.click('#btn-demo');page.wait_for_timeout(800)
 assert page.locator('#v-word').inner_text()=='COMPROMISED'
 with page.expect_download() as d:page.click('#export-report')
 d.value.save_as(str(ROOT/'release/sample-report.html'))
 print('download',d.value.suggested_filename)
 for tab in ['events','stories','playbooks','ai','dashboard']:page.click(f'nav button[data-t={tab}]')
 page.screenshot(path=str(ROOT/'release/screenshots/investigation.png'),full_page=True)
 for w,h in [(375,812),(812,375)]:
  page.set_viewport_size({'width':w,'height':h})
  widths=page.evaluate('[document.documentElement.scrollWidth,innerWidth]');print('widths',widths)
  assert widths[0]<=widths[1], 'Horizontal overflow'
 page.set_viewport_size({'width':375,'height':812});page.screenshot(path=str(ROOT/'release/screenshots/mobile.png'),full_page=True)
 page.emulate_media(reduced_motion='reduce')
 assert page.locator('#live-start').evaluate('el=>getComputedStyle(el).transitionDuration')=='0s'
 print('errors',errs);assert not errs
 b.close()
