const {test} = require('node:test');
const assert = require('node:assert/strict');
const S = require('../backup-security.js');
const fixture = () => ({config:{nombre:'Trabajador',sueldo:629997,horas:42,diasComp:7},v4Migrated:true,
  jornadas:[{id:'j1',fecha:'2026-11-09',tipo:'normal',entrada:'08:00',salida:'21:50',nota:'Prueba'}],
  comp:[],fin:[],bolsillos:[{id:'b1',nombre:'Casa',cuenta:'Ahorro'}],
  movB:[{id:'m1',bolsilloId:'b1',fecha:'2026-11-09',tipo:'aporte',monto:10000}]});

test('valid current backup and minimal legacy backup',()=>{
  assert.deepEqual(S.parse(JSON.stringify(fixture())),fixture());
  assert.doesNotThrow(()=>S.validate({config:{},jornadas:[]}));
});
const invalid = {
  'executable ID': x=>x.jornadas[0].id="'+(globalThis.pwned=1)+'",
  'attribute injection ID': x=>x.bolsillos[0].id='\" onmouseover=alert(1)',
  'invalid date': x=>x.jornadas[0].fecha='2026-02-30',
  'HTML date': x=>x.jornadas[0].fecha='<img src=x onerror=alert(1)>',
  'HTML time': x=>x.jornadas[0].entrada='<img src=x onerror=alert(1)>',
  'reversed times': x=>x.jornadas[0].salida='07:00',
  'unknown day type': x=>x.jornadas[0].tipo='unknown',
  'duplicate IDs': x=>x.jornadas.push({...x.jornadas[0]}),
  'null collection': x=>x.fin=null,
  'nonarray collection': x=>x.comp={},
  'string amount': x=>x.movB[0].monto='1000',
  'negative amount': x=>x.movB[0].monto=-5,
  'infinite amount': x=>x.movB[0].monto=Infinity,
  'fractional compensation interval': x=>x.config.diasComp=1.5,
  'missing pocket reference': x=>x.movB[0].bolsilloId='missing',
  'extra root key': x=>x.evil={},
  'extra nested key': x=>x.config.evil={},
  'extra row key': x=>x.jornadas[0].evil={},
  'invalid compensation count': x=>x.comp=[{id:'c',fecha:'2026-11-10',fechaFin:'2026-11-11',tipo:'uso',cantidad:1}],
  'inconsistent compensation dates': x=>x.comp=[{id:'c',fecha:'2026-11-10',tipo:'uso',cantidad:1,fechas:['2026-11-11']}],
  'oversized text': x=>x.jornadas[0].nota='a'.repeat(2001),
  'too many records': x=>x.jornadas=Array.from({length:10001},(_,i)=>({...x.jornadas[0],id:'j'+i}))
};
for (const [name, mutate] of Object.entries(invalid)) test('reject '+name,()=>{
  const x=fixture();mutate(x);assert.throws(()=>S.validate(x));
});
test('reject malformed JSON, dangerous keys and oversized files',()=>{
  for (const raw of ['{invalid','null','[]','{"config":{},"jornadas":[],"__proto__":{"polluted":true}}',
    '{"config":{"constructor":{}},"jornadas":[]}', ' '.repeat(S.MAX_BYTES+1)]) assert.throws(()=>S.parse(raw));
  assert.equal({}.polluted,undefined);
});
test('valid compensation range, legacy savings and free text',()=>{
  const x=fixture();x.comp=[{id:'c1',fecha:'2026-11-10',fechaFin:'2026-11-11',fechas:['2026-11-10','2026-11-11'],cantidad:2,tipo:'uso'}];
  x.fin=[{fecha:'2026-11-09',tipo:'ahorro',monto:10,objetivo:'Casa',banco:'Banco'}];
  x.jornadas[0].nota='<script>untrusted text stays text</script>';
  assert.doesNotThrow(()=>S.validate(x));
});
test('merge adds records without replacing data or configuration; idempotent',()=>{
  const a=fixture(),b=fixture();b.config.sueldo=1;b.jornadas.push({...b.jornadas[0],id:'j2',fecha:'2026-11-10'});
  const before=JSON.stringify(a),merged=S.merge(a,b);
  assert.equal(merged.jornadas.length,2);assert.equal(merged.config.sueldo,a.config.sueldo);
  assert.equal(JSON.stringify(a),before);assert.deepEqual(S.merge(merged,b),merged);
});
test('merge conflict rejects entire import without mutating original',()=>{
  const a=fixture(),b=fixture(),before=JSON.stringify(a);b.jornadas[0].salida='22:00';
  assert.throws(()=>S.merge(a,b),/mismo ID/);assert.equal(JSON.stringify(a),before);
});
