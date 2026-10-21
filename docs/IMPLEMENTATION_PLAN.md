# Plan incremental para Luna

Cada fila es una tarea separada y revisable. No implementar todo en una sola entrega.
T00–T11 y la validación real C14 están completos. D01 (lector compatible) y D02
(preflight de scope/contexto) de la entrega 0.2 están completos; D03 es el siguiente.

| ID / dependencia | Objetivo y componentes | Cambios esperados | Pruebas / aceptación | Riesgo o decisión resuelta |
|---|---|---|---|---|
| T00 / ninguna — completo | Bootstrap | Package Python 3.12, CLI help/version, lock y pytest/Ruff; `scan` explícitamente pendiente | Cuatro pruebas de bootstrap y wheel instalado desde fuera del checkout | psutil y Pydantic runtime; sin Typer/Rich |
| T01 / T00 — completo | models.py y schema | Modelos estrictos 1.0.0, referencias/tiempos, JSON Schema Draft 2020-12 y tres fixtures | 13 pruebas de modelo; schema y relaciones/socket unknown validados | Cambios incompatibles requieren nueva versión de esquema |
| T02 / T01 — completo | runner.py | Completo: systemctl allowlisted, argv acotado, PATH de sistema fijo, stdin cerrado, captura incremental y deadlines de hasta 30 s | 8 pruebas: timeout, salida limitada, stderr secreto descartado, status no cero, shell literal, env mínimo, lookup fuera de cwd | Sin shell; stderr sólo tiene conteo; timeout mata el grupo de procesos |
| T03 / T02 — completo | scan.py workers | Supervisor secuencial spawn, contexto con deadlines, RLIMIT_AS <=256 MiB, JSON IPC acotado a 8 MiB, timeouts y limpieza de grupo de procesos | 14 pruebas: resultado JSON, límite de memoria, error saneado, worker/global timeout, límite IPC, descendientes terminados, collector importado dentro del worker y validación de parámetros | Evitar deadlock del pipe; no hacer threading no cancelable |
| T04a / T03 — completo | collectors/host.py OS y recursos | Parser acotado de os-release sin shell, kernel/hostname/boot ID, CPU/memoria, UID/EUID y namespaces; evidencia del host y recursos | 7 pruebas: Ubuntu/RHEL sintéticos, syntax adversaria no ejecutada, fallback, datos malformados, permiso denegado y namespace desconocido | Sin source del archivo ni machine-id; RHEL real sigue sin probar |
| T04b / T04a — completo | host.py filesystems | disk_partitions(all=False), disk_usage por montaje, IDs/evidencia deterministas y máximo 256 | 5 pruebas: orden/evidencia, error por montaje, enumeración denegada, límite truncado, capacidad cero y entrada inválida | El método de psutil filtra su alcance; no inspeccionar red ni corregir permisos |
| T04c / T04a — completo | host.py interfaces | net_if_addrs/net_if_stats, IPs/prefijos canónicos, zonas IPv6 y máximo 256 | 6 pruebas: IP/máscara/zona, error independiente de cada fuente, zona no resuelta, dirección inválida y límite truncado | Se omiten familias no IP/MAC; sin inferir exposición |
| T05 / T03,T04a — completo | processes.py | PID, create_time, nombre y UID observables; límite 10.000; fallos por campo y carrera conservan datos | 6 pruebas: campos/evidencia ordenados, desaparición, permiso UID, iterator denegado, truncamiento y canarios de datos prohibidos | Sólo lectura; no argv/env/cwd/open_files; PID no es identidad entre scans |
| T06 / T05 — completo | sockets.py | TCP LISTEN/UDP bound, IPv4/IPv6 y relación owned_by revalidada; límite 20.000 y presupuesto IPC | 7 pruebas unitarias + listener Linux real: filtros, PID null/reutilizado, permisos, zona IPv6, truncamiento y cierre | Sin conexiones salientes; visibilidad sin root siempre parcial |
| T07 / T03,T05 — completo | systemd.py | Detección de capacidad/runtime, servicios cargados, propiedades allowlisted y MainPID revalidado | 6 pruebas: unsupported, manager desconectado, allowlist/redacción, PID 0/malformado, vínculo estable/carrera y límite | C14 real pasó en Actions; unidades cargadas no equivalen a todas instaladas |
| T08 / T04b,T07 — completo | assessment.py | FS_USAGE_HIGH, SYSTEMD_FAILED, evaluaciones y referencias basadas sólo en snapshot | 7 pruebas: umbral exacto 90%, positivos/negativos, capacidad cero, dato faltante, estados systemd y unsupported | No health score ni puertos como riesgo |
| T09 / T01,T08 — completo | reporting.py | Validación de snapshot, JSON acotado, escritura privada atómica, resumen saneado | 7 pruebas: JSON/0600, overwrite, symlink, falla/limpieza, carrera no-replace y ANSI/controles | Directorio hostil fuera de alcance; no dump arbitrario |
| T10 / T04c,T06,T07,T09 — completo | cli/scan integración | Workers → snapshot validado → reglas → JSON privado y resumen; códigos e interrupción | 8 pruebas CLI + scan Linux no root; A1–A9; muestra Debian 13/Python 3.12: 0,85 s, RSS muestreado del árbol 62,3 MiB, JSON 49.449 bytes | Muestra puntual, no SLA; RHEL/WSL no declarados probados |
| T11 / T10 — completo | CI y documentación de uso | Workflow Ubuntu/Python 3.12, checks, wheel y job systemd separado; README de uso | CI completa; C14 pasó en runner Ubuntu con manager real; workflow exige root y preflight | Workflow no sube snapshots; RHEL/WSL no declarados probados |

Orden recomendado: T00 → T01 → T02 → T03 → T04a/b/c → T05 → T06 → T07 → T08 →
T09 → T10 → T11. No generar código de fases futuras al crear estructura.

## Definition of done por tarea

Diff pequeño, sin cambios ajenos, contrato y docs coherentes. Checks ejecutados con
resultado y conteo; fallos y skips visibles. Ninguna operación mutante dentro del
scan. No publicar paquetes. El usuario autorizó pushes revisados a `origin/main` al
terminar cada tarea validada. Si se descubre que la
spec no se puede cumplir, documentar el bloqueo concreto antes de cambiar su
semántica. No saltar una prueba fallida sustituyéndola por un test trivial.

## Gate de versión 0.1

Wheel instalable desde fuera del repo, scan no root válido, listener controlado,
dos reglas verificadas, errores/cobertura/persistencia correctos y sin canarios de
secretos. Objetivos de recursos medidos. Las pruebas reales de systemd determinan
si esa capacidad puede declararse validada; fixtures no bastan. No ejecutar en
corporativo para suplir un lab ausente.

## Backlog posterior, excluido de la implementación inicial

| Entrega | Pasos pequeños y dependencias | Gate |
|---|---|---|
| 0.2 diff | **D01 lector — completo; D02 preflight scope/contexto — completo; D03 servicios — completo; D04 matching de listeners — completo**; D05 salida added/removed/changed/not_comparable — siguiente | Sin falsos removed cuando falta cobertura, mismo namespace; ignorar PID/UUID y recursos volátiles |
| 0.3 Docker opcional | Decisión de privilegio; proyección de campos; colector explícito; lab on/off/denied | Sin env/labels/inspect completo persistido, sin instalar daemon ni conceder docker group |
| SSH | Inventario autorizado; OpenSSH BatchMode/host keys; empaquetado remoto; recuperar JSON; timeouts por host | Ningún host desconocido aceptado automáticamente; credenciales fuera del snapshot |
| Mapping | Casos reales; contratos explícitos de arista; fuente y verificación; revisión humana | No equiparar conexión con dependencia; no escaneo lateral |

D01 entrega `load_snapshot(path)`: limita el archivo a 16 MiB, rechaza claves JSON
duplicadas y números no finitos, acepta sólo major 1, valida todos los campos
conocidos y conserva intacto el documento original para no perder extensiones
aditivas. Los tipos y enums críticos desconocidos se rechazan. No implementa todavía
clasificación ni salida de diferencias.

D02 entrega `preflight_comparison(before, after)`: requiere scope UUID de operador
idéntico, schema major igual y valores conocidos e idénticos para uid/euid y los
namespaces pid/net/mnt. Devuelve códigos de bloqueo en orden estable; no ofrece
override ni calcula cambios. Un boot_id distinto no bloquea un diff del mismo scope.

D03 entrega `match_services(before, after)`: usa sólo `ServiceAttributes.name`; ignora
IDs locales, estado y PID. Devuelve matches y claves de un solo lado en orden estable.
Un nombre duplicado en cualquiera de los snapshots queda ambiguo y no se asigna como
matched, added o removed.

D04 entrega `match_sockets(before, after)`: usa protocolo, familia, dirección local,
puerto y scope_id IPv6; ignora PID y ordena resultados por clave. Claves duplicadas
quedan ambiguas y no se emparejan.

Para diff, scope UUID igual no basta si cambió namespace o no puede verificarse:
por defecto rechazar comparación global; en una versión futura permitir override
explícito que conserve la advertencia. No llamar removed a una unidad que pasó a
no cargada: list-units sólo prueba `no_longer_observed_loaded`, no desinstalación.
