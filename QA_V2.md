# QA — Mi Control V2

Fecha: 2026-11-03

## Pruebas de lógica realizadas

| Caso | Resultado esperado | Estado |
|---|---:|---|
| Lunes: HE desde 16:30, salida 21:50 | 5 h 20 min | OK |
| Miércoles: HE desde 17:30, salida 21:15 | 3 h 45 min | OK |
| Sábado: HE desde 08:00, salida 20:52 | 12 h 52 min | OK |
| Domingo trabajado | TRATO, 0 HE | OK |
| 6 días trabajados | 0 comp., progreso 6/7 | OK |
| 7 días trabajados | 1 comp., progreso 0/7 | OK |
| 14 días trabajados | 2 comp., progreso 0/7 | OK |
| Progreso al cambiar de mes | No se reinicia | OK |
| Tomar compensativos con saldo 0 | Acción no disponible | OK |
| Tomar compensativos con saldo > 0 | Toma todos los disponibles | OK |
| Salida anterior/igual a entrada | Bloqueada | OK |
| Jornada duplicada | Solicita confirmación | OK |
| Editar/eliminar jornada | Recalcula totales | OK |
| Monto financiero <= 0 | Bloqueado | OK |
| Editar/eliminar movimiento financiero | Disponible | OK |
| Respaldo JSON | Exportación/importación incorporada | OK |
| Exportación Excel | CSV UTF-8 con separador ; | OK |

## Cambios UX V2

- Se eliminó el selector visible `Usé 1 / Ajuste +1 / Ajuste -1`.
- Si no hay compensativos disponibles, la app solo muestra el progreso hacia el próximo.
- Si hay saldo, ofrece una única acción para registrar todos los compensativos disponibles como tomados.
- Los ajustes manuales quedaron en Configuración como corrección excepcional.
- Jornadas y movimientos financieros ahora pueden editarse y eliminarse.
- Se añadió respaldo completo JSON además de exportación CSV.

## Pendiente antes de producción

- QA visual real en iPhone y Android.
- Publicación por HTTPS para probar PWA/service worker correctamente.
- Autenticación y sincronización en nube antes de usar datos reales entre varios dispositivos/usuarios.
- Pruebas E2E automatizadas en navegador cuando la estructura de UI se estabilice.
