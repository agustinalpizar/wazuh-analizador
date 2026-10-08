// Ejecutar: node --test tests/
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { parseInput, analyze, classifyIPv4, parseTimestamp } = require('../js/analyzer.js');
const sample = require('../js/sample.js');

const ok = (obj) => parseInput(JSON.stringify(obj));

test('el ejemplo se valida y se analiza', () => {
  const p = ok(sample);
  assert.equal(p.ok, true);
  assert.deepEqual(p.warnings, []);
  const r = analyze(p.event);
  assert.equal(r.severity.level, 10);
  assert.equal(r.severity.ruleId, '5763');
  assert.equal(r.agent.name, 'srv-demo-01');
  assert.equal(r.time.utc, '2026-10-04T22:13:07.512Z');
  assert.match(r.summary.sentence, /5763/);
  assert.ok(r.inferences.length >= 3);
  assert.ok(r.inferences.every((i) => i.basis.length > 0));
  // Las inferencias solo citan campos que existen en el evento.
  assert.ok(!r.inferences.some((i) => i.basis.includes('data.srcuser')));
});

test('el archivo de ejemplo coincide con el ejemplo del código', () => {
  const file = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'ejemplos', 'ejemplo-ssh-fuerza-bruta.json'), 'utf8'));
  assert.deepEqual(file, sample);
});

test('JSON inválido da error claro con línea y columna', () => {
  const p = parseInput('{\n  "rule": {\n    "id": 1,\n  }\n}');
  assert.equal(p.ok, false);
  assert.match(p.errors[0], /no es JSON válido/);
  assert.match(p.errors[0], /línea \d+, columna \d+/);
});

test('entrada vacía, no objeto, lista múltiple y sin rule se rechazan', () => {
  assert.equal(parseInput('   ').ok, false);
  assert.equal(parseInput('42').ok, false);
  assert.equal(parseInput('[{},{}]').ok, false);
  const p = parseInput('{"agent":{"name":"x"}}');
  assert.equal(p.ok, false);
  assert.match(p.errors[0], /rule/);
});

test('campos faltantes producen avisos y "no disponible", sin inventar', () => {
  const p = ok({ rule: { description: 'algo' } });
  assert.equal(p.ok, true);
  assert.ok(p.warnings.some((w) => w.includes('rule.id')));
  assert.ok(p.warnings.some((w) => w.includes('timestamp')));
  const r = analyze(p.event);
  assert.equal(r.agent.name, null);
  assert.equal(r.time.raw, null);
  assert.equal(r.severity.level, null);
  assert.match(r.summary.sentence, /no disponible/);
  assert.ok(r.missing.fields.some((f) => f.path === 'agent.name'));
});

test('nivel no numérico avisa y no se ubica en la escala', () => {
  const p = ok({ rule: { id: '1', level: 'alto', description: 'x' } });
  assert.ok(p.warnings.some((w) => w.includes('rule.level')));
  assert.equal(analyze(p.event).severity.title, null);
});

test('formato _source (OpenSearch) se desenvuelve', () => {
  const p = ok({ _index: 'wazuh-alerts', _source: sample });
  assert.equal(p.ok, true);
  assert.equal(p.event.rule.id, '5763');
});

test('alerta no reconocida no recibe interpretación inventada', () => {
  const r = analyze(ok({ rule: { id: '99', level: 1, description: 'otra cosa', groups: ['x'] } }).event);
  assert.equal(r.inferences.length, 1);
  assert.match(r.inferences[0].text, /no coincide/);
});

test('texto malicioso en el log se conserva como dato, sin tocarlo', () => {
  const evil = '<img src=x onerror=alert(1)>';
  const r = analyze(ok({ rule: { id: '1', level: 3, description: evil }, full_log: evil }).event);
  assert.ok(r.evidence.flatMap((g) => g.fields).some((f) => f.value === evil));
});

test('utilidades', () => {
  assert.match(classifyIPv4('10.1.2.3'), /privada/);
  assert.match(classifyIPv4('203.0.113.9'), /documentación/);
  assert.match(classifyIPv4('8.8.8.8'), /podría ser pública/);
  assert.equal(classifyIPv4('999.1.1.1'), null);
  assert.equal(parseTimestamp('no es fecha'), null);
});
