"""Isolated browser regression/security tests. No requests reach Supabase or a CDN."""
import functools
import http.server
import json
import os
from pathlib import Path
import threading
import unittest
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(ROOT)))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}/'
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH', '/usr/bin/chromium'), headless=True, args=['--no-sandbox'])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.pw.stop()
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.contexts = []
        self.errors = []
        self.external = []

    def tearDown(self):
        for c in self.contexts:
            c.close()
        self.assertEqual(self.errors, [], 'unexpected JavaScript errors')

    def open(self, storage=None, service_workers='block'):
        c = self.browser.new_context(service_workers=service_workers, timezone_id='America/Santiago', accept_downloads=True)
        self.contexts.append(c)
        def route(r):
            if urlparse(r.request.url).hostname == '127.0.0.1':
                r.continue_()
            else:
                self.external.append(r.request.url)
                r.abort()
        c.route('**/*', route)
        page = c.new_page()
        page.on('pageerror', lambda e: self.errors.append(str(e)))
        if storage:
            # Seed once, not on reload; all records are synthetic.
            page.goto(self.url, wait_until='networkidle')
            page.evaluate('(s)=>{for(const [k,v] of Object.entries(s)) localStorage.setItem(k,v)}', storage)
        page.goto(self.url, wait_until='networkidle')
        return page

    def sample(self, page):
        return page.evaluate('({...db,jornadas:[{id:"j1",fecha:"2026-11-09",tipo:"normal",entrada:"08:00",salida:"21:50",nota:""}]})')

    def import_file(self, page, value):
        page.locator('#tabs button[data-p="historial"]').click()
        raw = value if isinstance(value, str) else json.dumps(value)
        page.locator('#importFile').set_input_files({'name':'synthetic.json','mimeType':'application/json','buffer':raw.encode()})

    def mock_cloud(self, page, remote=None):
        if remote is not None:
            remote.setdefault('actualizado_en','2026-11-01T00:00:00.000Z')
        page.evaluate('''(remote) => {
          window.__calls=0;window.__remote=remote;window.__writes=0;window.__race=null;window.__readError=false;
          window.supabase={createClient:()=>{window.__calls++;return {
            auth:{getSession:async()=>({data:{session:{user:{id:'synthetic-user'}}},error:null})},
            from:()=>({
              select:()=>({eq:()=>({maybeSingle:async()=>({data:structuredClone(window.__remote),error:window.__readError?{message:'read failed'}:null})})}),
              insert:(row)=>({select:async()=>{
                if(window.__race)window.__remote=window.__race;
                if(window.__remote)return {data:null,error:{message:'duplicate key'}};
                window.__writes++;window.__remote=structuredClone(row);return {data:[{user_id:row.user_id}],error:null};
              }}),
              update:(row)=>{
                const filters={};const q={eq:(k,v)=>{filters[k]=v;return q},select:async()=>{
                  if(window.__race)window.__remote=window.__race;
                  if(!window.__remote || window.__remote.actualizado_en!==filters.actualizado_en)return {data:[],error:null};
                  window.__writes++;Object.assign(window.__remote,structuredClone(row));return {data:[{user_id:'synthetic-user'}],error:null};
                }};return q;
              }
            })
          }}};
        }''',remote)

    def test_no_network_before_consent_even_with_legacy_auto_on(self):
        page = self.open({'turnop-auto-backup-v1':'on'})
        page.evaluate('autoBackup()')
        page.wait_for_timeout(4200)
        self.assertEqual(self.external, [])
        self.assertFalse(page.evaluate('autoEnabled()'))
        self.assertEqual(page.locator('script[src*="supabase"]').count(), 0)

    def test_malicious_import_rejected_without_changes(self):
        page = self.open()
        for field, payload in [('id', "'+(window.__pwned=1)+'"), ('entrada','<img src=x onerror="window.__pwned=1">'), ('fecha','2026-02-30')]:
            sample = self.sample(page)
            sample['jornadas'][0][field] = payload
            before = page.evaluate('JSON.stringify(db)')
            self.import_file(page, sample)
            page.locator('#appNoticeText').wait_for(state='visible')
            self.assertEqual(page.evaluate('JSON.stringify(db)'), before)
            self.assertIsNone(page.evaluate('localStorage.getItem(K)'))
            self.assertIsNone(page.evaluate('window.__pwned'))
            page.locator('.appNotice .noticeClose').click()

    def test_defense_in_depth_render_never_evaluates_ids_or_fields(self):
        page = self.open()
        # Bypass validation deliberately to test safe rendering independently.
        page.evaluate('''() => { db.jornadas=[{id:"\\\" onpointerover=\\\"window.__pwned=1",fecha:"<img src=x onerror=window.__pwned=1>",tipo:"no_trabajado",entrada:"",salida:""}];renderJ(); }''')
        self.assertEqual(page.locator('#listaJ img').count(), 0)
        self.assertEqual(page.locator('#listaJ [onclick],#listaJ [onpointerover]').count(), 0)
        page.locator('#listaJ button').first.dispatch_event('pointerover')
        self.assertIsNone(page.evaluate('window.__pwned'))

    def test_import_adds_preserves_config_and_original_snapshot_and_is_idempotent(self):
        page = self.open()
        sample = self.sample(page)
        self.import_file(page, sample)
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.jornadas.length===1')
        original = page.evaluate('localStorage.getItem(K)')
        sample['jornadas'].append({**sample['jornadas'][0], 'id':'j2','fecha':'2026-11-10'})
        sample['config']['sueldo'] = 1
        self.import_file(page, sample)
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.jornadas.length===2')
        self.assertEqual(page.evaluate('db.config.sueldo'), 629997)
        archives = page.evaluate('Object.keys(localStorage).filter(k=>k.startsWith("turnop-before-import-")).map(k=>JSON.parse(localStorage.getItem(k)).current)')
        self.assertIn(original, archives)
        self.import_file(page, sample)
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.jornadas.length===2')
        page.reload(wait_until='networkidle')
        self.assertEqual(page.evaluate('db.jornadas.length'), 2)

    def test_cancel_conflict_and_quota_failure_do_not_change_data(self):
        page = self.open()
        sample = self.sample(page)
        self.import_file(page, sample)
        page.locator('.confirmCancel').click()
        self.assertIsNone(page.evaluate('localStorage.getItem(K)'))
        self.import_file(page, sample)
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.jornadas.length===1')
        before = page.evaluate('localStorage.getItem(K)')
        sample['jornadas'][0]['salida']='22:00'
        self.import_file(page, sample)
        page.locator('#appNoticeText').wait_for(state='visible')
        self.assertEqual(page.evaluate('localStorage.getItem(K)'),before)
        page.locator('.appNotice .noticeClose').click()
        sample['jornadas'][0]['id']='j2'
        page.evaluate('() => {Storage.prototype.setItem=function(){throw new DOMException("Quota exceeded","QuotaExceededError")}}')
        self.import_file(page, sample)
        page.locator('.confirmAccept').click()
        page.locator('#appNoticeText').wait_for(state='visible')
        self.assertEqual(page.evaluate('localStorage.getItem(K)'),before)
        self.assertEqual(page.evaluate('db.jornadas.length'),1)

    def test_corrupt_current_and_legacy_stay_byte_exact_and_exportable(self):
        for key, raw in [('miControlV2','{invalid-json'),('miControlV1',''),('miControlV2','{"config":{},"jornadas":null}')]:
            page = self.open({key:raw})
            self.assertTrue(page.locator('#recoveryNotice').is_visible())
            self.assertTrue(page.evaluate('document.querySelector("main").inert'))
            self.assertEqual(page.evaluate('(k)=>localStorage.getItem(k)',key), raw)
            self.assertFalse(page.evaluate('cloudAllowed()'))
            self.assertTrue(page.evaluate('()=>{try {persist();return false} catch {return true}}'))
            with page.expect_download() as download:
                page.locator('#downloadRecovery').click()
            self.assertEqual(json.loads(Path(download.value.path()).read_text())[key],raw)
            page.reload(wait_until='networkidle')
            self.assertEqual(page.evaluate('(k)=>localStorage.getItem(k)',key),raw)
        self.assertEqual(self.external,[])

    def test_legacy_valid_data_not_rewritten_on_open(self):
        raw=json.dumps({'config':{},'jornadas':[{'fecha':'2026-11-09','tipo':'normal','entrada':'08:00','salida':'21:50'}], 'fin':[{'fecha':'2026-11-09','tipo':'ahorro','monto':1000,'objetivo':'Casa','banco':'Ahorro'}]})
        page=self.open({'miControlV1':raw})
        self.assertFalse(page.evaluate('storageBlocked'))
        self.assertEqual(page.evaluate('db.jornadas.length'),1)
        self.assertEqual(page.evaluate('db.bolsillos.length'),1)
        self.assertEqual(page.evaluate('saldoB(db.bolsillos[0].id)'),1000)
        self.assertIsNone(page.evaluate('localStorage.getItem(K)'))
        self.assertEqual(page.evaluate('localStorage.getItem(OLD)'),raw)

    def test_legacy_import_is_idempotent_including_savings_migration(self):
        page=self.open()
        legacy={'config':{},'jornadas':[{'fecha':'2026-11-09','tipo':'normal','entrada':'08:00','salida':'21:50'}],
                'fin':[{'fecha':'2026-11-09','tipo':'ahorro','monto':1000,'objetivo':'Casa','banco':'Ahorro'}]}
        for _ in range(2):
            self.import_file(page,legacy)
            page.locator('.confirmAccept').click()
            page.wait_for_function('db.jornadas.length===1 && db.movB.length===1')
        self.assertEqual(page.evaluate('db.bolsillos.length'),1)
        self.assertEqual(page.evaluate('saldoB(db.bolsillos[0].id)'),1000)

    def test_remote_restore_uses_same_validation_and_does_not_replace_data(self):
        page=self.open()
        sample=self.sample(page)
        self.import_file(page,sample)
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.jornadas.length===1')
        before=page.evaluate('localStorage.getItem(K)')
        sample['jornadas'][0]['id']="'+(window.__pwned=1)+'"
        page.evaluate('''(data) => {
          localStorage.setItem(CONSENT_KEY,'accepted');
          window.supabase={createClient:()=>({auth:{getSession:async()=>({data:{session:{user:{id:'test'}}}})},
          from:()=>({select:()=>({eq:()=>({maybeSingle:async()=>({data:{datos:data},error:null})})})})})};
        }''',sample)
        page.evaluate('restaurarRespaldoNube()')
        self.assertIn('inválido',page.locator('#cloudStatus').text_content())
        self.assertEqual(page.evaluate('localStorage.getItem(K)'),before)
        self.assertEqual(page.evaluate('db.jornadas.length'),1)
        self.assertEqual(self.external,[])

    def test_storage_quota_during_normal_edit_preserves_last_saved_state(self):
        page=self.open()
        sample=self.sample(page)
        self.import_file(page,sample)
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.jornadas.length===1')
        before=page.evaluate('localStorage.getItem(K)')
        page.evaluate('''() => {Storage.prototype.setItem=function(){throw new DOMException('Full','QuotaExceededError')};
          db.jornadas[0].salida='22:00';save('changed');}''')
        page.locator('#appNoticeText').wait_for(state='visible')
        self.assertEqual(page.evaluate('localStorage.getItem(K)'),before)
        self.assertEqual(page.evaluate('db.jornadas[0].salida'),'21:50')

    def test_consent_cancel_accept_revoke_with_mock_sdk(self):
        page = self.open()
        self.mock_cloud(page)
        page.locator('#tabs button[data-p="historial"]').click()
        page.get_by_role('button',name='Guardar respaldo en nube',exact=True).click()
        page.locator('.confirmCancel').click()
        self.assertEqual(page.evaluate('window.__calls'),0)
        self.assertFalse(page.evaluate('cloudAllowed()'))
        page.get_by_role('button',name='Guardar respaldo en nube',exact=True).click()
        page.get_by_role('button',name='Permitir respaldo',exact=True).click()
        page.wait_for_function('window.__remote!==null')
        self.assertTrue(page.evaluate('cloudAllowed()'))
        self.assertFalse(page.evaluate('autoEnabled()'))
        page.locator('#cloudAutoBtn').click()
        page.get_by_role('button',name='Activar respaldo automático',exact=True).last.click()
        page.wait_for_function('autoEnabled()')
        page.get_by_role('button',name='Desactivar nube',exact=True).click()
        self.assertFalse(page.evaluate('autoEnabled()'))
        self.assertFalse(page.evaluate('cloudAllowed()'))
        page.evaluate('autoBackup()')
        self.assertEqual(page.evaluate('window.__calls'),1)
        self.assertEqual(self.external,[])

    def test_legacy_auto_on_stays_off_after_general_consent_and_reload(self):
        page=self.open({'turnop-auto-backup-v1':'on'})
        self.mock_cloud(page)
        page.locator('#tabs button[data-p="historial"]').click()
        page.get_by_role('button',name='Guardar respaldo en nube',exact=True).click()
        page.get_by_role('button',name='Permitir respaldo',exact=True).click()
        page.wait_for_function('window.__writes===1')
        self.assertFalse(page.evaluate('autoEnabled()'))
        self.assertEqual(page.evaluate('localStorage.getItem("turnop-auto-backup-v1")'),'on')
        page.reload(wait_until='networkidle')
        self.assertFalse(page.evaluate('autoEnabled()'))
        self.assertEqual(self.external,[])

    def test_auto_requires_specific_confirmation_even_with_general_consent(self):
        page=self.open({'turnop-auto-backup-v1':'on','turnop-cloud-consent-v1':'accepted'})
        remote={'user_id':'synthetic-user','datos':page.evaluate('db')}
        self.mock_cloud(page,remote)
        page.locator('#tabs button[data-p="historial"]').click()
        page.locator('#cloudAutoBtn').click()
        self.assertEqual(page.locator('.confirmAccept').text_content(),'Activar respaldo automático')
        page.locator('.confirmCancel').click()
        self.assertFalse(page.evaluate('autoEnabled()'))
        self.assertEqual(page.evaluate('window.__calls'),0)
        page.locator('#cloudAutoBtn').click()
        page.locator('.confirmAccept').click()
        page.wait_for_function('autoEnabled()')
        page.reload(wait_until='networkidle')
        self.assertTrue(page.evaluate('autoEnabled()'))
        page.evaluate('revokeCloudConsent()')

    def test_confirmation_labels_are_local_and_reset_after_consent(self):
        for answer in ('cancel','accept','escape'):
            page=self.open()
            page.evaluate('() => {window.__permission=requireCloudConsent()}')
            self.assertEqual(page.locator('.confirmAccept').text_content(),'Permitir respaldo')
            self.assertEqual(page.locator('.confirmCancel').text_content(),'Cancelar')
            if answer=='escape':page.keyboard.press('Escape')
            else:page.locator('.confirmAccept' if answer=='accept' else '.confirmCancel').click()
            page.evaluate('() => {window.__ordinary=confirmarAccion("Eliminar un registro de prueba")}')
            self.assertEqual(page.locator('.confirmAccept').text_content(),'Confirmar')
            self.assertEqual(page.locator('.confirmCancel').text_content(),'Cancelar')
            page.locator('.confirmCancel').click()
        # A pre-existing ordinary dialog must not have its labels mutated globally.
        page=self.open()
        page.evaluate('() => {window.__ordinary=confirmarAccion("Acción normal");window.__permission=requireCloudConsent()}')
        dialogs=page.locator('.confirmOverlay')
        self.assertEqual(dialogs.nth(0).locator('.confirmAccept').text_content(),'Confirmar')
        self.assertEqual(dialogs.nth(1).locator('.confirmAccept').text_content(),'Permitir respaldo')
        dialogs.nth(1).locator('.confirmCancel').click()
        dialogs.nth(0).locator('.confirmCancel').click()

    def test_manual_backup_blocks_unknown_different_remote(self):
        page=self.open({'turnop-cloud-consent-v1':'accepted'})
        remote={'user_id':'synthetic-user','datos':self.sample(page)}
        self.mock_cloud(page,remote)
        page.evaluate('subirRespaldoNube()')
        self.assertIn('remoto diferente',page.locator('#cloudStatus').text_content())
        self.assertEqual(page.evaluate('window.__remote'),remote)
        self.assertEqual(page.evaluate('window.__writes'),0)

    def test_manual_backup_unchanged_remote_is_noop(self):
        page=self.open({'turnop-cloud-consent-v1':'accepted'})
        remote={'user_id':'synthetic-user','datos':page.evaluate('db')}
        self.mock_cloud(page,remote)
        page.evaluate('subirRespaldoNube()')
        self.assertEqual(page.evaluate('window.__writes'),0)
        self.assertIn('guardado',page.locator('#cloudStatus').text_content())

    def test_manual_backup_never_removes_remote_records_even_with_known_baseline(self):
        page=self.open({'turnop-cloud-consent-v1':'accepted'})
        remote={'user_id':'synthetic-user','datos':self.sample(page)}
        self.mock_cloud(page,remote)
        page.evaluate('() => {lastCloudSnapshot=cloudStable(window.__remote.datos)}')
        page.evaluate('subirRespaldoNube()')
        self.assertEqual(page.evaluate('window.__writes'),0)
        self.assertEqual(page.evaluate('window.__remote'),remote)
        self.assertIn('registros que faltan',page.locator('#cloudStatus').text_content())

    def test_manual_backup_updates_only_known_unchanged_baseline(self):
        page=self.open({'turnop-cloud-consent-v1':'accepted'})
        remote={'user_id':'synthetic-user','datos':page.evaluate('db')}
        self.mock_cloud(page,remote)
        page.evaluate('() => {lastCloudSnapshot=cloudStable(window.__remote.datos);db.config.nombre="Actualizado"}')
        page.evaluate('subirRespaldoNube()')
        self.assertEqual(page.evaluate('window.__writes'),1)
        self.assertEqual(page.evaluate('window.__remote.datos.config.nombre'),'Actualizado')

    def test_manual_backup_revision_invalid_blocks_and_future_clock_advances(self):
        for stamp in ('invalid-revision','2090-01-01T00:00:00.000Z'):
            page=self.open({'turnop-cloud-consent-v1':'accepted'})
            remote={'user_id':'synthetic-user','datos':page.evaluate('db'),'actualizado_en':stamp}
            self.mock_cloud(page,remote)
            page.evaluate('() => {lastCloudSnapshot=cloudStable(window.__remote.datos);db.config.nombre="Actualizado"}')
            page.evaluate('subirRespaldoNube()')
            if stamp=='invalid-revision':
                self.assertEqual(page.evaluate('window.__writes'),0)
                self.assertEqual(page.evaluate('window.__remote'),remote)
            else:
                self.assertEqual(page.evaluate('window.__writes'),1)
                self.assertEqual(page.evaluate('window.__remote.actualizado_en'),'2090-01-01T00:00:00.001Z')

    def test_manual_backup_concurrent_update_and_insert_do_not_overwrite(self):
        for exists in (True,False):
            page=self.open({'turnop-cloud-consent-v1':'accepted'})
            remote={'user_id':'synthetic-user','datos':page.evaluate('db')}
            self.mock_cloud(page,remote if exists else None)
            concurrent={'user_id':'synthetic-user','datos':self.sample(page),'actualizado_en':'2026-11-02T00:00:00.000Z'}
            page.evaluate('''(race) => {window.__race=race;lastCloudSnapshot=cloudStable(db);db.config.nombre='Cambio local';}''',concurrent)
            page.evaluate('subirRespaldoNube()')
            self.assertEqual(page.evaluate('window.__writes'),0)
            self.assertEqual(page.evaluate('window.__remote'),concurrent)
            self.assertIn('No se pudo respaldar',page.locator('#cloudStatus').text_content())

    def test_manual_backup_read_error_or_invalid_remote_never_writes(self):
        for invalid in (False,True):
            page=self.open({'turnop-cloud-consent-v1':'accepted'})
            remote={'user_id':'synthetic-user','datos':{'config':{},'jornadas':None}} if invalid else None
            self.mock_cloud(page,remote)
            if not invalid:page.evaluate('window.__readError=true')
            page.evaluate('subirRespaldoNube()')
            self.assertEqual(page.evaluate('window.__writes'),0)
            self.assertEqual(page.evaluate('window.__remote'),remote)
            self.assertIn('No se pudo respaldar',page.locator('#cloudStatus').text_content())

    def test_overtime_money_compensation_and_edit_delete_regression(self):
        page=self.open()
        result=page.evaluate('''() => {
          const dates=['2026-11-09','2026-11-10','2026-11-11','2026-11-12','2026-11-13','2026-11-14','2026-11-15'];
          db.jornadas=dates.map((fecha,i)=>({id:'j'+i,fecha,tipo:'normal',entrada:'08:00',salida:i===2?'21:15':i===5?'20:52':'21:50',nota:''}));
          return {he:[calcJ(db.jornadas[0]).he,calcJ(db.jornadas[2]).he,calcJ(db.jornadas[5]).he],sunday:calcJ(db.jornadas[6]),comp:compStats(),summary:summary('2026-11','calendario')};
        }''')
        self.assertEqual(result['he'],[320,225,772])
        self.assertEqual(result['sunday'],{'he':0,'trato':True,'trabajo':True})
        self.assertEqual(result['comp']['available'],1)
        self.assertAlmostEqual(result['summary']['heMoney'],result['summary']['he']/60*5250)
        page.evaluate('render();save()')
        page.locator('#tabs button[data-p="jornadas"]').click()
        page.locator('[data-record-action="editJ"][data-id="j0"]').click()
        page.locator('#jSalida').fill('22:00')
        page.locator('#jGuardar').click()
        page.wait_for_function('db.jornadas.find(j=>j.id==="j0").salida==="22:00"')
        page.locator('[data-record-action="delJ"][data-id="j0"]').click()
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.jornadas.length===6')
        self.assertEqual(page.evaluate('compStats().available'),0)
        page.reload(wait_until='networkidle')
        self.assertEqual(page.evaluate('db.jornadas.length'),6)

    def test_compensation_and_pocket_actions_remain_functional(self):
        page=self.open()
        page.evaluate('''() => { db.comp=[{id:'c1',fecha:'2026-11-10',tipo:'uso',cantidad:1}];db.bolsillos=[{id:'b1',nombre:'Casa',cuenta:'Ahorro'}];db.movB=[{id:'m1',bolsilloId:'b1',fecha:'2026-11-09',tipo:'aporte',monto:1000}];render(); }''')
        # These existing features are hidden by the current product layout.
        page.locator('[data-record-action="anularComp"]').evaluate('(el)=>el.click()')
        page.locator('.confirmAccept').click()
        page.wait_for_function('db.comp.length===0')
        page.locator('[data-record-action="abrirMovB"][data-mode="retiro"]').evaluate('(el)=>el.click()')
        page.locator('#movBMonto').fill('500',force=True) if page.locator('#movBMonto').is_visible() else page.evaluate('movBMonto.value="500"')
        page.evaluate('guardarMovB()')
        self.assertEqual(page.evaluate('saldoB("b1")'),500)
        self.assertEqual(page.evaluate('db.movB.length'),2)

    def test_other_tab_change_is_not_overwritten(self):
        page=self.open()
        raw=json.dumps(self.sample(page))
        page.evaluate('(raw)=>localStorage.setItem(K,raw)',raw)
        self.assertTrue(page.evaluate('()=>{try {persist();return false} catch {return true}}'))
        self.assertEqual(page.evaluate('localStorage.getItem(K)'),raw)
        self.assertTrue(page.evaluate('storageBlocked'))

    def test_pwa_offline_reload_caches_validator(self):
        page=self.open(service_workers='allow')
        page.evaluate('navigator.serviceWorker.ready')
        page.reload(wait_until='networkidle')
        page.evaluate('''() => { db.jornadas=[{id:'offline',fecha:'2026-11-09',tipo:'normal',entrada:'08:00',salida:'21:50'}];save(); }''')
        page.context.set_offline(True)
        page.reload(wait_until='domcontentloaded')
        self.assertEqual(page.evaluate('db.jornadas.length'),1)
        self.assertEqual(page.evaluate('typeof BackupSecurity.parse'),'function')
        self.assertFalse(page.evaluate('storageBlocked'))


if __name__ == '__main__':
    unittest.main()
