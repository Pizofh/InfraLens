# Plan incremental para Luna

Cada fila es una tarea separada y revisable. No implementar todo en una sola entrega.
T00–T04b están completos; los checks de filas posteriores son requisitos futuros.

| ID / dependencia | Objetivo y componentes | Cambios esperados | Pruebas / aceptación | Riesgo o decisión resuelta |
|---|---|---|---|---|
| T00 / ninguna — completo | Bootstrap | Package Python 3.12, CLI help/version, lock y pytest/Ruff; `scan` explícitamente pendiente | Cuatro pruebas de bootstrap y wheel instalado desde fuera del checkout | psutil y Pydantic runtime; sin Typer/Rich |
| T01 / T00 — completo | models.py y schema | Modelos estrictos 1.0.0, referencias/tiempos, JSON Schema Draft 2020-12 y tres fixtures | 13 pruebas de modelo; schema y relaciones/socket unknown validados | Cambios incompatibles requieren nueva versión de esquema |
| T02 / T01 — completo | runner.py | Completo: systemctl allowlisted, argv acotado, PATH de sistema fijo, stdin cerrado, captura incremental y deadlines de hasta 30 s | 8 pruebas: timeout, salida limitada, stderr secreto descartado, status no cero, shell literal, env mínimo, lookup fuera de cwd | Sin shell; stderr sólo tiene conteo; timeout mata el grupo de procesos |
| T03 / T02 — completo | scan.py workers | Supervisor secuencial spawn, contexto con deadlines, RLIMIT_AS <=256 MiB, JSON IPC acotado a 8 MiB, timeouts y limpieza de grupo de procesos | 14 pruebas: resultado JSON, límite de memoria, error saneado, worker/global timeout, límite IPC, descendientes terminados, collector importado dentro del worker y validación de parámetros | Evitar deadlock del pipe; no hacer threading no cancelable |
| T04a / T03 — completo | collectors/host.py OS y recursos | Parser acotado de os-release sin shell, kernel/hostname/boot ID, CPU/memoria, UID/EUID y namespaces; evidencia del host y recursos | 7 pruebas: Ubuntu/RHEL sintéticos, syntax adversaria no ejecutada, fallback, datos malformados, permiso denegado y namespace desconocido | Sin source del archivo ni machine-id; RHEL real sigue sin probar |
| T04b / T04a — completo | host.py filesystems | disk_partitions(all=False), disk_usage por montaje, IDs/evidencia deterministas y máximo 256 | 5 pruebas: orden/evidencia, error por montaje, enumeración denegada, límite truncado, capacidad cero y entrada inválida | El método de psutil filtra su alcance; no inspeccionar red ni corregir permisos |
| T04c / T04a — completo | host.py interfaces | net_if_addrs/net_if_stats, IPs/prefijos canónicos, zonas IPv6 y máximo 256 | 6 pruebas: IP/máscara/zona, error independiente de cada fuente, zona no resuelta, dirección inválida y límite truncado | Se omiten familias no IP/MAC; sin inferir exposición |
| T05 / T03,T04a | processes.py | Inventario mínimo y manejo de desaparición | C04/C05, UID desconocido, truncamiento, canarios argv/env | Nunca leer argv/env; PID no es identidad |
| T06 / T05 | sockets.py | TCP LISTEN/UDP bound y relación owned_by con revalidación | C05/C06/C13, PID null/reutilizado, sin root partial | No conexiones salientes ni etiquetas de aplicación |
| T07 / T03,T05 | systemd.py | Detección de capacidad, list-units/show allowlist, main_process verificado | C07; fixtures y C14 en host capaz antes de declarar soporte | Cargadas no equivale a todas instaladas; sin bus no se oculta error |
| T08 / T04b,T07 | assessment.py | FS_USAGE_HIGH, SYSTEMD_FAILED, evaluaciones y referencias | C08: límite 90%, negativos, no evaluables y cobertura parcial por objeto | No health score ni puertos como riesgo |
| T09 / T01,T08 | reporting.py | JSON 0600, validación, atomicidad, resumen y escape de controles | C09/C11, no sobrescritura por carrera, error de espacio/permisos | Directorio hostil fuera de alcance; no dump arbitrario |
| T10 / T04c,T06,T07,T09 | cli/scan integración | Conectar implementación, códigos, interrupción, límites | A1–A9, C12/C13; medir memoria/tiempo/tamaño, scan no root | No añadir flags fuera de spec para resolver bugs |
| T11 / T10 | CI y documentación de uso | Jobs base, wheel, capacidades systemd separadas, instrucciones instalación | C01–C13/C15 pasan, C14 pasa o capacidad queda sin verificar; conteos y versiones | No compatibilidad RHEL/WSL inventada; no artifacts sensibles |

Orden recomendado: T00 → T01 → T02 → T03 → T04a/b/c → T05 → T06 → T07 → T08 →
T09 → T10 → T11. No generar código de fases futuras al crear estructura.

## Definition of done por tarea

Diff pequeño, sin cambios ajenos, contrato y docs coherentes. Checks ejecutados con
resultado y conteo; fallos y skips visibles. Ninguna operación mutante dentro del
scan. No publicar paquetes ni empujar cambios sin petición. Si se descubre que la
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
| 0.2 diff | D01 lector compatible; D02 preflight scope/contexto; D03 servicios por nombre; D04 listeners; D05 salida added/removed/changed/not_comparable | Sin falsos removed cuando falta cobertura, mismo namespace; ignorar PID/UUID y recursos volátiles |
| 0.3 Docker opcional | Decisión de privilegio; proyección de campos; colector explícito; lab on/off/denied | Sin env/labels/inspect completo persistido, sin instalar daemon ni conceder docker group |
| SSH | Inventario autorizado; OpenSSH BatchMode/host keys; empaquetado remoto; recuperar JSON; timeouts por host | Ningún host desconocido aceptado automáticamente; credenciales fuera del snapshot |
| Mapping | Casos reales; contratos explícitos de arista; fuente y verificación; revisión humana | No equiparar conexión con dependencia; no escaneo lateral |

Para diff, scope UUID igual no basta si cambió namespace o no puede verificarse:
por defecto rechazar comparación global; en una versión futura permitir override
explícito que conserve la advertencia. No llamar removed a una unidad que pasó a
no cargada: list-units sólo prueba `no_longer_observed_loaded`, no desinstalación.
