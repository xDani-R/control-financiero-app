# Contención de seguridad v1

## Comportamiento

- Los JSON locales, importados y recuperados de nube se validan antes de normalizarlos. Se admiten formatos anteriores conocidos con campos opcionales; no se convierten tipos ambiguos. Límite: 5 MiB, 10.000 registros totales y 2.000 caracteres por texto. Se rechazan campos desconocidos, IDs no seguros/duplicados, referencias inválidas, cantidades fuera de rango, fechas imposibles y horarios inconsistentes.
- Los botones de registros usan atributos escapados y listeners con una lista cerrada de acciones. Los IDs ya no se evalúan como JavaScript. Las fechas y horas renderizadas también se escapan.
- Abrir la aplicación no escribe ni migra el almacenamiento persistente. Ante datos inválidos o inaccesibles se bloquean escrituras y nube; el contenido original sigue en su clave y puede descargarse desde el aviso de recuperación. No hay reparación destructiva automática. Si el navegador impide leer el almacenamiento, solo se puede exportar lo que pudo leerse.
- Las importaciones JSON y restauraciones de nube **agregan** registros: no reemplazan los existentes ni la configuración local. Un mismo ID con contenido distinto rechaza toda la importación. Se conserva una copia local previa bajo una clave `turnop-before-import-…` antes de escribir; si no hay espacio, no se importa. Los IDs omitidos de respaldos antiguos se derivan del contenido para que repetir la misma importación no duplique registros. La configuración del respaldo se valida, pero debe revisarse/copiarse manualmente si se quiere aplicarla.
- Las copias previas no se purgan automáticamente y ocupan cuota del navegador. Son archivos internos de recuperación en texto claro; no son cifrado ni una garantía frente a pérdida del perfil/dispositivo. Para revisión técnica, se pueden leer/exportar las claves `turnop-before-import-…` desde las herramientas del navegador; no borrar el almacenamiento al investigar un fallo.
- Se verifica que el almacenamiento no haya cambiado desde su lectura antes de escribir. Si otra pestaña lo cambia, se bloquea la escritura y se conserva también el contenido observado para recuperación. Esto evita sobrescrituras secuenciales de pestañas desactualizadas; localStorage no ofrece transacciones entre pestañas, por lo que no resuelve carreras simultáneas absolutas.
- La nube empieza desactivada, incluso si una versión anterior dejó el respaldo automático activado. La primera acción de nube requiere confirmar qué datos se enviarán, la ausencia de E2EE y los límites de la sesión anónima. El SDK externo se carga solo después del consentimiento. El respaldo automático requiere una confirmación específica adicional y un respaldo manual coincidente. Se usa una preferencia nueva `turnop-auto-backup-v2`; el valor heredado de v1 se conserva pero nunca habilita el automatismo, incluso después del consentimiento general. Los textos de cada diálogo se configuran de forma local, con Confirmar/Cancelar por defecto. Desactivar nube impide nuevas operaciones; una petición que ya fue enviada puede terminar.

## Pruebas reproducibles

No se necesitan dependencias para servir la aplicación ni para las pruebas de validación:

```sh
node --test tests/backup-security.test.cjs
```

Para pruebas de navegador, usar Python 3.12+ y Chromium. Si Playwright no está instalado, preparar un entorno de desarrollo local:

```sh
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements.txt
CHROMIUM_PATH=/usr/bin/chromium .venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

En el entorno cloud actual Python Playwright ya está instalado; basta `python3 -m unittest discover -s tests -p 'test_*.py' -v`. El runner inicia un servidor local en un puerto libre, crea contextos desechables y bloquea peticiones externas. Las pruebas de nube usan un SDK simulado en memoria; no contactan con Supabase ni usan credenciales. Ninguna prueba utiliza el perfil o datos del trabajador. La prueba PWA habilita service workers solo en su contexto desechable.

La suite cubre cargas manipuladas, protección adicional del render, integridad del estado y copias previas, cuotas, datos corruptos/legados, consentimiento, restauración remota simulada, cálculo de HE/dinero/compensativos, acciones de edición/eliminación y funcionamiento offline del validador.

## Fuera de alcance y pendientes

No se implementa E2EE, identidad recuperable ni gestión de dispositivos. Los datos locales, exportaciones y respaldos autorizados siguen legibles. No se modifican Supabase, RLS ni SQL y no se verificaron los permisos remotos reales. El respaldo manual consulta el remoto, rechaza diferencias sin una base previamente conocida y registros remotos ausentes localmente, y usa INSERT sin upsert o UPDATE condicional por la revisión `actualizado_en`, con verificación de filas afectadas y sin incluir datos laborales en URLs. Las escrituras de esta versión avanzan esa marca al menos un milisegundo; una revisión ausente/inválida o un error de permisos bloquea la actualización, sin recurrir a escritura ciega. La protección presupone que todos los escritores renuevan esa marca: clientes antiguos o externos que la reutilicen no ofrecen la misma garantía. Esto se prueba con un servidor simulado y necesita validación posterior en staging autorizado. El respaldo automático conserva sus limitaciones de concurrencia y necesita revisión independiente. El SDK sigue usando la versión mayor flotante existente: fijación/SRI, CSP, exportación CSV segura y revisión de entrega de la PWA siguen pendientes.

Las pestañas que continúen ejecutando una versión anterior no adquieren estas protecciones hasta actualizarse. La validación conservadora puede bloquear registros antiguos fuera del esquema conocido; se preservan para revisión, no se descartan ni se convierten silenciosamente. El modo de recuperación requiere asistencia para corregir una copia; no habilita automáticamente la edición del original corrupto.

Esta rama no debe desplegarse automáticamente. Revisar en PR y probar en dispositivos móviles antes de autorizar publicación. No incluye merge ni cambios de producción.
