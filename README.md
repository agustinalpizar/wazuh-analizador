# Analizador de alertas Wazuh

Aplicación web **local y educativa** para leer una alerta de Wazuh en formato JSON y separar:

- **Dato observado** (azul): lo que está literalmente en el evento.
- **Derivado** (gris): cálculos simples (p. ej. fecha convertida a UTC, rango de una IP) o texto de la documentación de Wazuh.
- **Posible interpretación** (ámbar, borde punteado): hipótesis cautelosas, cada una con los campos en que se apoya.

Una alerta indica que una regla de detección se cumplió; **no es prueba definitiva de un ataque**.

## Cómo ejecutarla

Requiere solo Python 3 (ya incluido en muchos equipos). Sin instalar nada más.

```bash
python -m http.server 8765 --bind 127.0.0.1
```

Abre <http://127.0.0.1:8765/index.html>. En Windows también puedes hacer doble clic en `iniciar.bat`.
Para detenerla, cierra la ventana o pulsa `Ctrl+C`.

## Cómo usarla

1. Pega un evento JSON, o pulsa **Cargar archivo JSON**, o **Cargar ejemplo ficticio**.
2. Pulsa **Analizar**.
3. Revisa las tarjetas: resumen, severidad y regla, agente, fecha/hora, evidencia, inferencias, información faltante y próximos pasos (solo lectura).

Archivos de prueba en `ejemplos/`: `ejemplo-ssh-fuerza-bruta.json` (válido, ficticio) y `json-invalido.json` (para ver la validación).

## Garantías de diseño

- **Sin red:** la página declara una política CSP (`connect-src 'none'`) que impide cualquier conexión saliente; no usa CDN, fuentes externas ni API de IA.
- **Sin persistencia:** no usa `localStorage`, cookies ni archivos; todo vive en memoria de la pestaña y se pierde al recargar. El botón **Limpiar todo** lo borra al instante.
- **Seguro ante logs hostiles:** el contenido del evento se inserta siempre como texto (`textContent`), nunca como HTML.
- **No inventa:** los campos ausentes se muestran como «no disponible» y se listan como información faltante.

## Estructura

```
index.html           Página única
css/styles.css       Estilos (claro/oscuro, adaptable a móvil)
js/analyzer.js       Validación y análisis (sin DOM; probado con Node)
js/app.js            Interfaz
js/sample.js         Evento ficticio
ejemplos/            JSON de prueba
tests/analyzer.test.js
iniciar.bat          Atajo para Windows
```

## Pruebas de la lógica

```bash
node --test tests/analyzer.test.js
```

## Límites

- Analiza **un** evento a la vez (acepta una lista de un elemento o el formato `_source` de OpenSearch).
- Las interpretaciones son reglas fijas y deliberadamente conservadoras para autenticación fallida/exitosa, integridad de archivos (syscheck), rootcheck, web, vulnerabilidades y SCA. Otros tipos de alerta reciben la evidencia y los pasos genéricos, sin interpretación.
- La escala de niveles viene de la documentación oficial (<https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html>); el color del nivel es solo orientativo.
- El ejemplo es **ficticio** y está modelado a partir del formato habitual de Wazuh; sus nombres de campo (p. ej. `data.dstuser`) conviene contrastarlos con una alerta real de tu versión antes de generalizar.
- No consulta reglas, reputación de IP ni inventarios: eso queda como paso manual.

## Proyecto relacionado

[**Nexo Lab**](https://github.com/agustinalpizar/nexo-lab): panel local para monitorizar y operar un laboratorio de VirtualBox (incluye un servidor Wazuh). Comparten el tema de leer alertas, pero no están integrados.

## Licencia

[MIT](LICENSE) © 2026 Agustín Alpízar Hernández.
