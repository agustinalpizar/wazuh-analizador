// Interfaz. Todo el contenido del evento se inserta con textContent (nunca innerHTML):
// los logs pueden contener texto controlado por un atacante.
(function () {
  'use strict';

  const MAX_BYTES = 2 * 1024 * 1024;
  const $ = (id) => document.getElementById(id);
  const entrada = $('entrada');
  const errores = $('errores');
  const resultado = $('resultado');
  const estadoArchivo = $('estado-archivo');

  function h(tag, attrs, ...kids) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') node.className = v;
      else node.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return node;
  }

  const TAGS = {
    observado: ['Dato observado', 'tag-obs'],
    derivado: ['Derivado (cálculo o documentación)', 'tag-der'],
    interpretacion: ['Posible interpretación', 'tag-int']
  };
  const tag = (kind) => h('span', { class: 'tag ' + TAGS[kind][1] }, TAGS[kind][0]);

  const missing = () => h('span', { class: 'na' }, 'no disponible en el evento');
  const val = (v) => (v == null ? missing() : v);

  function card(title, kind, ...body) {
    return h('section', { class: 'card result ' + kind }, h('div', { class: 'card-head' }, h('h2', null, title), TAGS[kind] && tag(kind)), ...body);
  }

  function dl(rows) {
    return h('dl', { class: 'facts' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, val(v))]));
  }

  function list(items, cls) {
    return h('ul', { class: cls || 'list' }, items.map((i) => h('li', null, i)));
  }

  function showErrors(errs) {
    errores.replaceChildren(
      h('strong', null, 'No se pudo analizar'),
      list(errs)
    );
    errores.hidden = false;
  }

  function clearErrors() {
    errores.replaceChildren();
    errores.hidden = true;
  }

  function render(parsed, report) {
    const { severity: s, agent: a, time: t } = report;
    const out = [];

    out.push(h('div', { class: 'caution' },
      h('strong', null, 'Cómo leer esto: '),
      'las tarjetas azules contienen datos que están en el evento; las tarjetas con borde punteado son hipótesis cautelosas, no conclusiones. Ninguna alerta, por sí sola, demuestra un ataque.'));

    if (parsed.warnings.length) {
      out.push(h('section', { class: 'card warn' }, h('h2', null, 'Avisos de validación'), list(parsed.warnings)));
    }

    out.push(card('Resumen del evento', 'observado',
      h('p', { class: 'lead' }, report.summary.sentence),
      h('p', { class: 'hint' }, 'Frase armada solo con campos del evento; lo que falta aparece como «no disponible».')));

    const sevBody = [
      h('div', { class: 'level-row' },
        h('span', { class: 'level band-' + (s.band || 'nd') }, s.rawLevel != null ? 'Nivel ' + s.rawLevel : 'Nivel no disponible'),
        s.title && h('span', { class: 'level-title' }, s.title)),
      dl([
        ['ID de regla', s.ruleId],
        ['Descripción', s.description],
        ['Grupos', s.groups.length ? s.groups.join(', ') : null],
        ['Veces activada (firedtimes)', s.firedtimes],
        ['MITRE ATT&CK', s.mitre && s.mitre.id.length ? s.mitre.id.join(', ') + (s.mitre.tactic.length ? ' · ' + s.mitre.tactic.join(', ') : '') + (s.mitre.technique.length ? ' · ' + s.mitre.technique.join(', ') : '') : null]
      ])
    ];
    out.push(card('Severidad y regla activada', 'observado', ...sevBody));
    if (s.docText) {
      out.push(h('section', { class: 'card result derivado' },
        h('div', { class: 'card-head' }, h('h2', null, 'Qué significa ese nivel según Wazuh'), tag('derivado')),
        h('p', null, s.docText),
        h('p', { class: 'hint' }, 'Texto resumido de la escala oficial de clasificación de reglas de Wazuh (documentation.wazuh.com → Rules classification). El color del nivel es solo orientativo de esta app.')));
    }

    out.push(card('Agente o equipo relacionado', 'observado', dl([
      ['Nombre', a.name], ['ID', a.id], ['IP', a.ip], ['Manager', a.manager]
    ])));

    out.push(card('Fecha y hora', 'observado', dl([
      ['Valor original (timestamp)', t.raw],
      ['Hora en el log (predecoder)', t.logTime]
    ]),
      t.utc && h('p', { class: 'derived-line' }, tag('derivado'), ' Convertido a UTC: ', h('code', null, t.utc)),
      t.raw && !t.utc && h('p', { class: 'hint' }, 'El valor no tiene un formato de fecha reconocible, así que no se convirtió.')));

    // Evidencia
    const ev = [h('p', { class: 'hint' }, 'Todos los campos presentes en el evento, tal cual llegaron (sin interpretar).')];
    for (const g of report.evidence) {
      ev.push(h('h3', null, g.group));
      ev.push(h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, 'Campo'), h('th', null, 'Valor'))),
        h('tbody', null, g.fields.map((f) => h('tr', null,
          h('td', null, h('code', null, f.path)),
          h('td', null, f.path === 'full_log' ? h('pre', null, f.value) : f.value)))))));
    }
    if (report.evidenceTruncated) ev.push(h('p', { class: 'hint' }, 'El evento tiene muchos campos; se muestran los primeros 400.'));
    out.push(card('Evidencia presente en el evento', 'observado', ...ev));

    // Interpretación
    out.push(card('Qué se puede inferir con cautela', 'interpretacion',
      h('p', { class: 'hint' }, 'Hipótesis, no hechos. Cada una indica en qué campos se apoya.'),
      h('ul', { class: 'list' }, report.inferences.map((i) => h('li', null,
        h('p', null, i.text),
        i.basis.length && h('p', { class: 'basis' }, 'Se apoya en: ', i.basis.map((b, k) => [k ? ', ' : '', h('code', null, b)])))))));

    // Faltante
    const m = report.missing;
    out.push(card('Qué información falta para confirmar', 'faltante',
      m.fields.length
        ? [h('h3', null, 'Campos ausentes en este evento'),
           h('ul', { class: 'list' }, m.fields.map((f) => h('li', null, h('code', null, f.path), ' — ', f.why)))]
        : h('p', { class: 'hint' }, 'No se detectaron campos esperados ausentes para este tipo de alerta.'),
      h('h3', null, 'Contexto que el evento no puede darte'),
      list(m.context)));

    // Pasos
    out.push(card('Próximos pasos de investigación (solo lectura)', 'pasos',
      h('p', { class: 'hint' }, 'Son consultas y comprobaciones que no modifican ningún sistema. Cualquier acción de contención (bloquear, aislar, cambiar credenciales) debe decidirla la persona responsable según su procedimiento; esta app no las ejecuta.'),
      h('ol', { class: 'list' }, report.nextSteps.map((x) => h('li', null, x)))));

    resultado.replaceChildren(...out);
    resultado.firstChild.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function analizar() {
    clearErrors();
    resultado.replaceChildren();
    const parsed = WazuhAnalyzer.parseInput(entrada.value);
    if (!parsed.ok) {
      showErrors(parsed.errors);
      errores.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    render(parsed, WazuhAnalyzer.analyze(parsed.event));
  }

  $('analizar').addEventListener('click', analizar);

  $('ejemplo').addEventListener('click', () => {
    entrada.value = JSON.stringify(WAZUH_EJEMPLO, null, 2);
    estadoArchivo.textContent = 'Ejemplo ficticio cargado (no corresponde a ningún sistema real).';
    clearErrors();
    analizar();
  });

  $('limpiar').addEventListener('click', () => {
    entrada.value = '';
    $('archivo').value = '';
    estadoArchivo.textContent = '';
    clearErrors();
    resultado.replaceChildren();
    entrada.focus();
  });

  $('archivo').addEventListener('change', async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    clearErrors();
    resultado.replaceChildren();
    if (f.size > MAX_BYTES) {
      showErrors([`El archivo pesa ${(f.size / 1048576).toFixed(1)} MB; el máximo para esta herramienta es 2 MB.`]);
      e.target.value = '';
      return;
    }
    try {
      entrada.value = await f.text();
      estadoArchivo.textContent = `Archivo cargado en el cuadro de texto: ${f.name}. Pulsa «Analizar».`;
    } catch (err) {
      showErrors(['No se pudo leer el archivo: ' + err.message]);
    }
    e.target.value = '';
  });

  entrada.addEventListener('input', () => { estadoArchivo.textContent = ''; });

  // Evita que el navegador restaure texto pegado tras recargar.
  entrada.value = '';
})();
