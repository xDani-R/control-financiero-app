/* Validation at every untrusted backup boundary; no DOM or network access. */
(function (root) {
  'use strict';
  const MAX_BYTES = 5 * 1024 * 1024, MAX_ROWS = 10000;
  const fail = (path) => { throw new Error('Respaldo inválido: ' + path); };
  const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  function object(value, keys, path) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(path);
    for (const k of Object.keys(value)) if (!keys.includes(k)) fail(path + '.' + k);
  }
  function text(v, path, max = 2000) {
    if (typeof v !== 'string' || v.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(v)) fail(path);
  }
  function number(v, path, min = 0, max = 1e12, integer = false) {
    if (typeof v !== 'number' || !Number.isFinite(v) || v < min || v > max || (integer && !Number.isInteger(v))) fail(path);
  }
  function date(v, path) {
    if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v) || v < '1900-01-01' || v > '2199-12-31') fail(path);
    const d = new Date(v + 'T12:00:00Z');
    if (!Number.isFinite(d.getTime()) || d.toISOString().slice(0, 10) !== v) fail(path);
  }
  function time(v, path, empty = false) {
    if (!(empty && v === '') && (typeof v !== 'string' || !/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(v))) fail(path);
  }
  function choice(v, values, path) { if (!values.includes(v)) fail(path); }
  function optional(o, key, check, path) { if (own(o, key)) check(o[key], path + '.' + key); }
  function validate(value) {
    object(value, ['config','jornadas','comp','fin','bolsillos','movB','v4Migrated'], 'raíz');
    object(value.config, ['nombre','sueldo','horas','valorHE','trato','gratificacion','asignaciones','tasaDescuentos','anticipo','diaCierre','diasComp','horarios'], 'config');
    if (!Array.isArray(value.jornadas)) fail('jornadas');
    const c = value.config;
    optional(c, 'nombre', text, 'config');
    for (const k of ['sueldo','valorHE','trato','gratificacion','asignaciones','anticipo']) optional(c, k, number, 'config');
    optional(c, 'horas', (v,p) => number(v,p,1,168), 'config');
    optional(c, 'tasaDescuentos', (v,p) => number(v,p,0,100), 'config');
    optional(c, 'diaCierre', (v,p) => number(v,p,1,28,true), 'config');
    optional(c, 'diasComp', (v,p) => number(v,p,1,10000,true), 'config');
    optional(c, 'horarios', (v,p) => {
      object(v, ['1','2','3','4','5','6','7'], p);
      for (const k of Object.keys(v)) time(v[k], p + '.' + k, true);
    }, 'config');
    optional(value, 'v4Migrated', (v,p) => { if (typeof v !== 'boolean') fail(p); }, 'raíz');
    const fields = {
      jornadas: ['id','fecha','tipo','entrada','salida','nota'],
      comp: ['id','fecha','fechaFin','fechas','tipo','cantidad','nota'],
      fin: ['id','fecha','tipo','monto','concepto','objetivo','banco'],
      bolsillos: ['id','nombre','cuenta','creado'],
      movB: ['id','bolsilloId','fecha','tipo','monto','nota']
    };
    let count = 0;
    for (const [name, keys] of Object.entries(fields)) {
      const rows = own(value, name) ? value[name] : [];
      if (!Array.isArray(rows) || (count += rows.length) > MAX_ROWS) fail(name + ' (máximo 10000 registros)');
      const ids = new Set();
      rows.forEach((r, i) => {
        const p = name + '[' + i + ']'; object(r, keys, p);
        optional(r, 'id', (v,q) => {
          if (typeof v !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(v) || ids.has(v)) fail(q);
          ids.add(v);
        }, p);
        for (const k of ['nota','concepto','objetivo','banco','nombre','cuenta']) optional(r,k,text,p);
        if (name === 'bolsillos') {
          text(r.nombre,p+'.nombre'); text(r.cuenta,p+'.cuenta');
          optional(r,'creado',date,p); return;
        }
        date(r.fecha,p+'.fecha');
        if (name === 'jornadas') {
          choice(r.tipo,['normal','festivo','no_trabajado'],p+'.tipo');
          time(r.entrada,p+'.entrada',r.tipo==='no_trabajado'); time(r.salida,p+'.salida',r.tipo==='no_trabajado');
          if (r.tipo !== 'no_trabajado' && r.salida <= r.entrada) fail(p+'.salida');
        } else if (name === 'comp') {
          choice(r.tipo,['uso','ajuste'],p+'.tipo');
          optional(r,'cantidad',(v,q)=>number(v,q,r.tipo==='uso'?1:-10000,10000,true),p);
          optional(r,'fechaFin',date,p);
          if (r.fechaFin && r.fechaFin < r.fecha) fail(p+'.fechaFin');
          if (r.tipo === 'uso') {
            const end = r.fechaFin || r.fecha;
            const days = Math.round((new Date(end+'T12:00Z')-new Date(r.fecha+'T12:00Z'))/86400000)+1;
            if (days > 366 || (r.cantidad ?? 1) !== days) fail(p+'.cantidad');
            optional(r,'fechas',(v,q)=>{
              if (!Array.isArray(v) || v.length !== days) fail(q);
              v.forEach((d,j)=>{date(d,q); if (d !== new Date(new Date(r.fecha+'T12:00Z').getTime()+j*86400000).toISOString().slice(0,10)) fail(q);});
            },p);
          } else if (own(r,'fechas') || own(r,'fechaFin')) fail(p);
        } else {
          number(r.monto,p+'.monto',0.01);
          if (name === 'movB') {
            choice(r.tipo,['aporte','retiro'],p+'.tipo');
            if (typeof r.bolsilloId !== 'string' || !(value.bolsillos || []).some(b=>b.id===r.bolsilloId)) fail(p+'.bolsilloId');
          } else optional(r,'tipo',(v,q)=>choice(v,['gasto','ahorro','ingreso'],q),p);
        }
      });
    }
    return value;
  }
  function parse(raw) {
    if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > MAX_BYTES) fail('tamaño (máximo 5 MiB)');
    return validate(JSON.parse(raw));
  }
  function stable(v) {
    if (Array.isArray(v)) return '['+v.map(stable).join(',')+']';
    if (v && typeof v==='object') return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}';
    return JSON.stringify(v);
  }
  // Never silently replace a record or local configuration during an import.
  function merge(current, incoming) {
    validate(current); validate(incoming);
    const result = JSON.parse(JSON.stringify(current));
    for (const key of ['jornadas','comp','fin','bolsillos','movB']) {
      result[key] ||= [];
      for (const row of incoming[key] || []) {
        const same = result[key].find(x=>x.id===row.id);
        if (same && stable(same)!==stable(row)) throw new Error('El respaldo contiene un registro diferente con el mismo ID. No se cambió ningún dato.');
        if (!same) result[key].push(JSON.parse(JSON.stringify(row)));
      }
    }
    return validate(result);
  }
  root.BackupSecurity = Object.freeze({MAX_BYTES, validate, parse, merge});
  if (typeof module !== 'undefined') module.exports = root.BackupSecurity;
})(typeof globalThis !== 'undefined' ? globalThis : window);
