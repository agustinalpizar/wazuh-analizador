// Lógica de análisis: sin DOM, sin red, sin almacenamiento. Funciona en navegador y en Node (tests).
// Regla de oro: solo se muestra lo que está en el evento; todo lo demás se rotula como "derivado"
// (cálculo o documentación) o "interpretación" (hipótesis cautelosa).
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.WazuhAnalyzer = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MAX_FIELDS = 400;

  // Escala oficial: https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html
  const LEVELS = {
    0: ['Ignorado', 'Sin acción. Se usa para evitar falsos positivos.'],
    2: ['Notificación de sistema de baja prioridad', 'Mensajes de estado; sin relevancia de seguridad.'],
    3: ['Evento exitoso/autorizado', 'Incluye inicios de sesión correctos, tráfico permitido por firewall, etc.'],
    4: ['Error de sistema de baja prioridad', 'Errores de configuración o dispositivos sin uso; normalmente sin relevancia de seguridad.'],
    5: ['Error generado por usuario', 'Contraseñas falladas, acciones denegadas, etc. Por sí solos, sin relevancia de seguridad.'],
    6: ['Ataque de baja relevancia', 'Gusanos o virus sin efecto en el sistema, eventos frecuentes de IDS.'],
    7: ['Coincidencia con "palabras malas"', 'Mensajes con "error", "bad", etc.; suelen estar sin clasificar y pueden tener relevancia.'],
    8: ['Visto por primera vez', 'Primera vez que se dispara un evento IDS o que un usuario inicia sesión; incluye acciones relevantes de seguridad.'],
    9: ['Error de origen inválido', 'Intentos con usuario desconocido o desde origen inválido; puede ser relevante, sobre todo si se repite.'],
    10: ['Múltiples errores generados por usuario', 'Varias contraseñas erróneas o inicios fallidos. Puede indicar un ataque o simplemente credenciales olvidadas.'],
    11: ['Aviso de verificación de integridad', 'Modificación de binarios o presencia de rootkits (Rootcheck). Puede indicar un ataque exitoso.'],
    12: ['Evento de alta importancia', 'Errores o avisos del sistema/kernel; pueden indicar un ataque contra una aplicación concreta.'],
    13: ['Error inusual (alta importancia)', 'La mayoría de las veces coincide con un patrón de ataque común.'],
    14: ['Evento de seguridad de alta importancia', 'Suele activarse por correlación e indica un ataque.'],
    15: ['Ataque grave', 'Sin posibilidad de falsos positivos según la clasificación; requiere atención inmediata.'],
    16: ['Severidad máxima', 'Reservado para reglas personalizadas; ninguna regla por defecto lo usa.']
  };

  const get = (obj, path) =>
    path.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), obj);

  const present = (v) => v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && v.length === 0);

  function formatValue(v) {
    if (v === null) return 'null';
    if (Array.isArray(v)) {
      return v.every((x) => x === null || typeof x !== 'object') ? v.join(', ') : JSON.stringify(v);
    }
    return String(v);
  }

  function flatten(obj, prefix, out, depth) {
    for (const [k, v] of Object.entries(obj)) {
      if (out.length >= MAX_FIELDS) return;
      const p = prefix ? prefix + '.' + k : k;
      if (v && typeof v === 'object' && !Array.isArray(v) && depth < 6) flatten(v, p, out, depth + 1);
      else out.push({ path: p, value: formatValue(v) });
    }
  }

  // ---------- Entrada y validación ----------

  function describeJsonError(err, text) {
    const msg = String(err && err.message ? err.message : err);
    let where = '';
    const m = /position (\d+)/.exec(msg);
    if (m) {
      const pos = Number(m[1]);
      const before = text.slice(0, pos).split('\n');
      where = ` (línea ${before.length}, columna ${before[before.length - 1].length + 1})`;
    }
    return `El texto no es JSON válido${where}. Detalle del navegador: ${msg}`;
  }

  function parseInput(text) {
    const errors = [];
    const warnings = [];
    const fail = () => ({ ok: false, event: null, errors, warnings });

    if (typeof text !== 'string' || text.trim() === '') {
      errors.push('No hay nada que analizar: pega un evento JSON o carga un archivo.');
      return fail();
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      errors.push(describeJsonError(e, text));
      errors.push('Causas frecuentes: comillas simples en lugar de dobles, coma final antes de } o ], texto cortado al copiar, o varias alertas pegadas una tras otra.');
      return fail();
    }

    if (Array.isArray(data)) {
      if (data.length !== 1) {
        errors.push(`El JSON es una lista con ${data.length} elementos. Esta versión analiza un solo evento a la vez: deja únicamente uno.`);
        return fail();
      }
      data = data[0];
      warnings.push('El JSON era una lista de un elemento; se analizó ese elemento.');
    }

    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
      errors.push('El JSON es válido, pero no es un objeto. Una alerta de Wazuh es un objeto con campos como "rule", "agent" y "timestamp".');
      return fail();
    }

    if (data._source && typeof data._source === 'object' && !Array.isArray(data._source)) {
      data = data._source;
      warnings.push('Se detectó formato de exportación de OpenSearch/Elasticsearch; se analizó el contenido de "_source".');
    }

    if (!data.rule || typeof data.rule !== 'object' || Array.isArray(data.rule)) {
      errors.push('Falta el objeto "rule". Sin él no se puede identificar la regla activada, así que esto no parece una alerta de Wazuh.');
      return fail();
    }

    const expected = [
      ['rule.id', 'ID de la regla'],
      ['rule.level', 'nivel de la regla'],
      ['rule.description', 'descripción de la regla'],
      ['agent.name', 'nombre del agente'],
      ['timestamp', 'fecha y hora'],
      ['full_log', 'log original']
    ];
    for (const [path, label] of expected) {
      if (!present(get(data, path))) warnings.push(`Falta el campo "${path}" (${label}). No se completará con suposiciones.`);
    }
    const lvl = get(data, 'rule.level');
    if (present(lvl) && !Number.isInteger(Number(lvl))) {
      warnings.push(`"rule.level" tiene el valor "${lvl}", que no es un número entero; no se puede ubicar en la escala.`);
    }

    return { ok: true, event: data, errors, warnings };
  }

  // ---------- Utilidades de derivación ----------

  function classifyIPv4(ip) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip));
    if (!m) return null;
    const [a, b, c, d] = m.slice(1).map(Number);
    if ([a, b, c, d].some((n) => n > 255)) return null;
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'privada (RFC 1918)';
    if (a === 127) return 'loopback';
    if (a === 169 && b === 254) return 'link-local';
    if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) {
      return 'reservada para documentación (RFC 5737)';
    }
    return 'fuera de los rangos privados/reservados comunes (podría ser pública)';
  }

  function parseTimestamp(raw) {
    if (typeof raw !== 'string') return null;
    // Wazuh escribe el desfase sin dos puntos (+0000); se normaliza solo para poder convertirlo.
    const norm = raw.replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
    const d = new Date(norm);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }

  function bandOf(level) {
    if (level <= 4) return 'bajo';
    if (level <= 7) return 'medio';
    if (level <= 11) return 'alto';
    return 'critico';
  }

  function groupOf(path) {
    const top = path.split('.')[0];
    if (top === 'timestamp' || top === 'id') return 'General';
    if (top === 'rule') return 'Regla';
    if (top === 'agent') return 'Agente';
    if (top === 'manager') return 'Manager';
    if (['decoder', 'predecoder', 'location', 'full_log'].includes(top)) return 'Origen del log';
    if (top === 'data') return 'Datos extraídos del log (data)';
    if (top === 'syscheck') return 'Integridad de archivos (syscheck)';
    return 'Otros campos';
  }
  const GROUP_ORDER = ['General', 'Regla', 'Agente', 'Manager', 'Origen del log', 'Datos extraídos del log (data)', 'Integridad de archivos (syscheck)', 'Otros campos'];

  // ---------- Análisis ----------

  function analyze(ev) {
    const rule = ev.rule || {};
    const groups = Array.isArray(rule.groups) ? rule.groups.map(String) : [];
    const inGroup = (...names) => names.some((n) => groups.includes(n));
    const desc = present(rule.description) ? String(rule.description) : '';

    const levelNum = present(rule.level) && Number.isInteger(Number(rule.level)) ? Number(rule.level) : null;
    const levelInfo = levelNum !== null ? LEVELS[levelNum] || null : null;

    const srcip = get(ev, 'data.srcip') ?? get(ev, 'data.win.eventdata.ipAddress');
    const user = get(ev, 'data.dstuser') ?? get(ev, 'data.srcuser') ?? get(ev, 'data.win.eventdata.targetUserName');
    const sysPath = get(ev, 'syscheck.path');

    // 1) Resumen: solo frases armadas con campos presentes.
    const na = '(no disponible)';
    const agentLabel = present(get(ev, 'agent.name'))
      ? ev.agent.name + (present(ev.agent.ip) ? ` (${ev.agent.ip})` : '')
      : na;
    const summary = {
      sentence:
        `La regla ${present(rule.id) ? rule.id : na} («${desc || na}») se activó con nivel ` +
        `${present(rule.level) ? rule.level : na} en el agente ${agentLabel}` +
        `, con fecha/hora ${present(ev.timestamp) ? ev.timestamp : na}.`
    };

    // 2) Severidad y regla
    const severity = {
      level: levelNum,
      rawLevel: present(rule.level) ? String(rule.level) : null,
      band: levelNum !== null ? bandOf(levelNum) : null,
      title: levelInfo ? levelInfo[0] : null,
      docText: levelInfo ? levelInfo[1] : null,
      ruleId: present(rule.id) ? String(rule.id) : null,
      description: desc || null,
      groups,
      firedtimes: present(rule.firedtimes) ? String(rule.firedtimes) : null,
      mitre: rule.mitre && typeof rule.mitre === 'object'
        ? {
            id: [].concat(rule.mitre.id ?? []).map(String),
            tactic: [].concat(rule.mitre.tactic ?? []).map(String),
            technique: [].concat(rule.mitre.technique ?? []).map(String)
          }
        : null
    };

    // 3) Agente
    const agent = {
      id: present(get(ev, 'agent.id')) ? String(ev.agent.id) : null,
      name: present(get(ev, 'agent.name')) ? String(ev.agent.name) : null,
      ip: present(get(ev, 'agent.ip')) ? String(ev.agent.ip) : null,
      manager: present(get(ev, 'manager.name')) ? String(ev.manager.name) : null
    };

    // 4) Fecha y hora
    const time = {
      raw: present(ev.timestamp) ? String(ev.timestamp) : null,
      utc: parseTimestamp(ev.timestamp),
      logTime: present(get(ev, 'predecoder.timestamp')) ? String(ev.predecoder.timestamp) : null
    };

    // 5) Evidencia observada (todo el evento, tal cual)
    const flat = [];
    flatten(ev, '', flat, 0);
    const byGroup = new Map();
    for (const f of flat) {
      const g = groupOf(f.path);
      if (!byGroup.has(g)) byGroup.set(g, []);
      byGroup.get(g).push(f);
    }
    const evidence = GROUP_ORDER.filter((g) => byGroup.has(g)).map((g) => ({ group: g, fields: byGroup.get(g) }));
    const truncated = flat.length >= MAX_FIELDS;

    // 6) Interpretaciones cautelosas (cada una cita los campos en que se apoya)
    const inferences = [];
    const infer = (text, basis) => inferences.push({ text, basis: basis.filter((b) => present(get(ev, b))) });

    const isAuthFail =
      inGroup('authentication_failed', 'authentication_failures', 'invalid_login') ||
      /authentication fail|failed password|invalid user|brute force|login fail|logon fail/i.test(desc);
    const isAuthOk = inGroup('authentication_success') && !isAuthFail;
    const isFim = inGroup('syscheck', 'syscheck_entry_modified', 'syscheck_entry_added', 'syscheck_entry_deleted') || present(get(ev, 'syscheck'));
    const isRootcheck = inGroup('rootcheck');
    const isWeb = inGroup('web', 'web_scan', 'accesslog', 'attack') && !isAuthFail;
    const isVuln = inGroup('vulnerability-detector');
    const isSca = inGroup('sca');

    if (isAuthFail) {
      infer(
        'La regla describe fallos de autenticación. Estos pueden deberse a una contraseña olvidada o mal escrita, a un servicio con credenciales desactualizadas, o a intentos de adivinar credenciales. El evento por sí solo no permite distinguir entre ellos.',
        ['rule.description', 'rule.groups']
      );
      if (present(rule.firedtimes)) {
        infer(
          `El campo rule.firedtimes indica ${rule.firedtimes} activación(es) de esta regla. Eso sugiere repetición, pero el evento no dice en qué ventana de tiempo ocurrieron ni si todas vinieron del mismo origen.`,
          ['rule.firedtimes']
        );
      }
      if (present(srcip)) {
        const cls = classifyIPv4(srcip);
        infer(
          `El log menciona una IP de origen (${srcip})${cls ? `, ${cls}` : ''}. Su rango no demuestra quién es el responsable ni su intención.`,
          ['data.srcip', 'full_log']
        );
      }
      if (present(user)) {
        const priv = /^(root|admin|administrator|administrador)$/i.test(String(user));
        infer(
          priv
            ? `La cuenta mencionada (${user}) es un nombre privilegiado muy común. Se prueba a menudo en intentos automatizados, pero también la usan administradores legítimos.`
            : `La cuenta mencionada es «${user}». El evento no indica si existe en el equipo ni si pertenece a una persona real; el log puede decirlo (p. ej. «invalid user»).`,
          ['data.dstuser', 'data.srcuser', 'full_log']
        );
      }
    }
    if (isAuthOk) {
      infer(
        'Se registró un inicio de sesión correcto. Por sí mismo suele ser actividad normal; solo cobra relevancia en contexto (usuario inesperado, horario inusual, origen desconocido).',
        ['rule.groups', 'rule.description']
      );
    }
    if (isFim) {
      infer(
        `Wazuh detectó un cambio de integridad${present(sysPath) ? ` en «${sysPath}»` : ''}${present(get(ev, 'syscheck.event')) ? ` (syscheck.event = ${ev.syscheck.event})` : ''}. Puede ser una actualización o cambio administrativo legítimo, o una modificación no autorizada; el evento solo prueba que el archivo cambió respecto a su línea base.`,
        ['syscheck.path', 'syscheck.event', 'rule.groups']
      );
    }
    if (isRootcheck) {
      infer(
        'Rootcheck marcó un hallazgo que coincide con una comprobación de rootkits o configuración. Estas comprobaciones pueden producir falsos positivos; conviene verificar el hallazgo concreto antes de sacar conclusiones.',
        ['rule.groups', 'rule.description']
      );
    }
    if (isWeb) {
      infer(
        'La petición web coincidió con un patrón de la regla. Eso no indica que el ataque tuviera éxito: hace falta ver la respuesta del servidor (código HTTP, tamaño) y si la aplicación es realmente vulnerable.',
        ['rule.groups', 'rule.description', 'full_log']
      );
    }
    if (isVuln) {
      infer(
        'La alerta señala software con una vulnerabilidad conocida según la base del detector. Indica exposición potencial, no que haya sido explotada.',
        ['rule.groups', 'rule.description']
      );
    }
    if (isSca) {
      infer(
        'La alerta indica una configuración que no cumple una política de evaluación (SCA). Es un hallazgo de endurecimiento, no necesariamente un incidente.',
        ['rule.groups', 'rule.description']
      );
    }
    if (severity.mitre && severity.mitre.id.length) {
      infer(
        `La regla está asociada a MITRE ATT&CK (${severity.mitre.id.join(', ')}${severity.mitre.technique.length ? ' · ' + severity.mitre.technique.join(', ') : ''}). Es una clasificación de la regla, no una confirmación de que esa técnica ocurriera.`,
        ['rule.mitre']
      );
    }
    if (levelInfo) {
      infer(
        `Según la documentación, el nivel ${levelNum} corresponde a «${levelInfo[0]}». El nivel es una prioridad asignada por la regla, no una medida del daño real.`,
        ['rule.level']
      );
    }
    if (inferences.length === 0) {
      infer('Este tipo de alerta no coincide con ninguna de las categorías que la app sabe interpretar; no se ofrece interpretación en lugar de inventarla. Guíate por la descripción de la regla y el log original.', ['rule.description']);
    }

    // 7) Qué falta para confirmar
    const missingFields = [];
    const need = (path, why) => { if (!present(get(ev, path))) missingFields.push({ path, why }); };
    need('timestamp', 'Sin fecha y hora no se puede correlacionar con otros eventos.');
    need('agent.name', 'No se sabe en qué equipo ocurrió.');
    need('full_log', 'Sin el log original solo se cuenta con la interpretación de Wazuh.');
    need('rule.id', 'No se puede consultar la definición de la regla.');
    need('rule.description', 'No se sabe qué detecta la regla.');
    if (isAuthFail) {
      if (!present(srcip)) missingFields.push({ path: 'data.srcip', why: 'No consta el origen de los intentos.' });
      if (!present(user)) missingFields.push({ path: 'data.dstuser', why: 'No consta qué cuenta fue objetivo.' });
    }
    if (isFim) {
      need('syscheck.path', 'No consta qué archivo cambió.');
      if (!present(get(ev, 'syscheck.audit.process.name')) && !present(get(ev, 'syscheck.uname_after'))) {
        missingFields.push({ path: 'syscheck.audit / uname_after', why: 'No consta quién o qué proceso hizo el cambio.' });
      }
    }

    const context = [
      'Si la actividad estaba autorizada o esperada (mantenimiento, pruebas, cambio planificado).',
      'Qué rol y criticidad tiene el equipo y si está expuesto a internet.',
      'Qué eventos ocurrieron antes y después en el mismo agente.',
      'Si esto es habitual en este equipo (línea base de comportamiento).'
    ];
    if (isAuthFail) {
      context.push('Si después de los fallos hubo un inicio de sesión exitoso desde el mismo origen.');
      if (present(srcip)) context.push('A quién pertenece la IP de origen según el inventario interno o registros públicos de asignación.');
    }
    if (isFim) context.push('Si existe un ticket de cambio o actualización que explique la modificación.');

    // 8) Próximos pasos: solo lectura, ninguno modifica sistemas.
    const nextSteps = [];
    nextSteps.push(`En el dashboard de Wazuh, filtra los eventos del mismo agente${present(get(ev, 'agent.name')) ? ` («${ev.agent.name}»)` : ''} unos 30 minutos antes y después de ${time.raw ? time.raw : 'la hora del evento'}.`);
    if (present(rule.id)) nextSteps.push(`Busca la regla ${rule.id} en otros agentes para ver si el patrón es aislado o está repartido.`);
    if (present(rule.id)) nextSteps.push(`Lee la definición de la regla ${rule.id} en el ruleset y la documentación de Wazuh para confirmar qué condiciones la activan.`);
    if (present(ev.location)) nextSteps.push(`Consulta el log original en la ubicación indicada («${ev.location}») del equipo, solo en modo lectura, y contrástalo con full_log.`);
    if (isAuthFail) {
      nextSteps.push('Revisa si, tras los fallos, aparece algún inicio de sesión exitoso (busca eventos de autenticación correcta del mismo usuario u origen).');
      if (present(srcip)) nextSteps.push(`Busca la IP ${srcip} en tus propios registros (otros agentes, firewall, proxy) para ver si aparece en más sitios. Es una consulta a tus datos, no un escaneo.`);
      nextSteps.push('Pregunta al responsable de la cuenta o del servicio si esperaba esos intentos.');
    }
    if (isFim) {
      nextSteps.push('Compara los hashes anterior y posterior del archivo si el evento los incluye, y confirma con quien administra el equipo si hubo una actualización o cambio.');
    }
    if (isWeb) nextSteps.push('Revisa en el log del servidor web la respuesta (código y tamaño) a las peticiones señaladas.');
    nextSteps.push('Anota qué campos del evento sostienen cada conclusión y cuáles son hipótesis, para poder revisarlo con otra persona.');

    return {
      summary, severity, agent, time, evidence, evidenceTruncated: truncated,
      inferences, missing: { fields: missingFields, context }, nextSteps
    };
  }

  return { parseInput, analyze, classifyIPv4, parseTimestamp, LEVELS };
});
