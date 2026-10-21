# Estrategia de pruebas

## Estado y presupuesto

Este documento prescribe pruebas para las capacidades todavía no implementadas.
La suite tiene 131 casos: 130 pasan localmente y C14 se omite porque este contenedor
no tiene manager systemd. C14 pasó en GitHub Actions sobre Ubuntu con manager real.
D01 cubre versiones, extensiones aditivas, tipos críticos y límites del lector;
D02 cubre scope operator, UID/EUID, namespaces conocidos y desconocidos, y schema
major. También cubre CLI, modelos,
contrato, schema, runner, supervisor y collector host aislado (OS, recursos, contexto,
filesystems, interfaces, procesos, sockets y systemd), assessment de las dos reglas,
persistencia JSON privada/atómica, resumen terminal saneado e integración CLI no root.
También incluye una prueba de integración del collector dentro del worker acotado.
No demuestra discovery integral,
compatibilidad del manager systemd, rendimiento del scan ni soporte RHEL/WSL.
Objetivo CI base sin servicios: unitarias + integración local no root en Ubuntu
24.04, Python 3.12; añadir 3.13 cuando las dependencias resueltas lo permitan.
No bloquear desarrollo en Windows por ausencia de Docker. Ejecutar CLI mediante
WSL2/Linux; import/help no implica compatibilidad de colectores en Windows.

## Matriz obligatoria de aceptación

| Caso | Nivel y entorno | Preparación | Resultado esperado |
|---|---|---|---|
| C01 contrato | Unidad | Ejemplos completos/parciales | Schema y referencias válidas; dangling refs, enums y tiempos inválidos rechazados |
| C02 OS | Unidad | Ubuntu/RHEL os-release, archivo faltante, quoted values | Parser sin shell; fallback y desconocidos explícitos |
| C03 recursos | Unidad | valores conocidos y total=0 | Bytes exactos, sin porcentajes inventados; regla no evaluable para total=0 |
| C04 permisos | Unidad | AccessDenied por objeto/colector | permission_denied y parcial/none; otro colector continúa |
| C05 carreras | Unidad | NoSuchProcess, PID reutilizado | Omisión limitada, sin vínculo falso |
| C06 sockets | Unidad | IPv4/6, wildcard, UDP, duplicados, pid null | Normalización y claves correctas; sólo TCP listen/UDP bound |
| C07 systemd | Unidad | sin ejecutable/runtime, bus caído, salida malformada | unsupported vs collection_error vs permission_denied distintos |
| C08 reglas | Unidad | FS 89.99/90/95%, total=0; failed/active/inactive | Umbral exacto, dos reglas, negativos sin finding; not_evaluable correcto; cobertura parcial se evalúa por sujeto observable |
| C09 seguridad | Unidad | canarios en argv/env/Description/stderr, ANSI y symlink | Ningún canario exportado, no shell/sudo, salida privada y terminal saneada |
| C10 límites | Unidad/integración worker | salida >1 MiB, exceso de records, proceso bloqueado | partial/truncated, deadline <=32 s, RLIMIT_AS efectivo, sin huérfanos ni buffers de comando ilimitados |
| C11 salida | Integración filesystem | ruta existente, falta permiso, symlink, interrupción | Códigos 1/2/130, archivo anterior intacto, temp limpio, modo 0600 |
| C12 CLI real | Integración Linux no root | Instalar wheel, ejecutar scan | JSON válido, resumen consistente, --fail-on-partial produce 3 si aplica |
| C13 listener | Integración Linux | Socket Python ligado a 127.0.0.1:0 mantenido abierto | Puerto elegido observado; tras cerrar deja de observarse; PID opcional |
| C14 systemd real | Integración VM/runner capaz | Unidad temporal propia failed, limpieza garantizada | SYSTEMD_FAILED sólo para unidad con estado failed observado |
| C15 regresión | Unidad | snapshots sanitizados congelados y lectura 1.x | Sin cambios involuntarios del contrato ni falsos removed |

C14 es requerida para declarar soporte de systemd, pero no para desarrollar scan
sin systemd. El job dedicado valida explícitamente el manager y ejecuta C14 como root;
si falta capacidad, falla en vez de contar un skip como éxito. C01–C13 y C15 son gate base, con
fixtures de systemd incluso cuando no corre C14.

## Fixtures y oráculos

Inyectar funciones proveedoras de psutil y runner; no mockear el propio resultado
que se intenta comprobar. Fixtures pequeñas de Ubuntu y RHEL provenientes de
salidas sintéticas o laboratorio, nunca dumps corporativos. Casos negativos por
cada parser y regla. Golden JSON elimina scan_id y timestamps variables antes de
comparar; no eliminar cobertura o errores. Semilla fija para datos adversarios.

Para socket real, el test crea listener, recibe el puerto asignado por el SO y
mantiene el objeto hasta completar el scan. No sleeps arbitrarios: coordinación
con Event/pipe y polling con deadline. Oráculo es getsockname(), no el colector.
Para permisos, mocks son deterministas; prueba real bajo usuario distinto sólo
cuando el runner lo permite, sin chmod de recursos del host. psutil puede ocultar
sockets: comprobar partial, no exigir ver procesos ajenos.

En systemd real usar unidad transitoria de test de nombre único con un comando
inocuo que termina con código no cero; no stop/restart de unidades existentes.
Harness de prueba, fuera del producto, puede necesitar privilegios específicos.
finally limpia únicamente su unidad y verifica limpieza; nunca elevar InfraLens.
Probar también estado inactive normal para impedir falso positivo failed.

## CI automatizada

1. Crear venv, resolver dependencias en lock revisable, instalar con modo frozen.
2. `ruff check .`, `ruff format --check .`.
3. `pytest -q tests/unit` y `pytest -q tests/integration -m 'not systemd and not docker'`.
4. `python -m build`; instalar wheel en venv limpio y ejecutar help, version y scan
   desde fuera del checkout. Verificar JSON y código documentado.
5. Job systemd separado: exigir manager accesible y ejecutar C14 como root.

Estos checks se ejecutan en `.github/workflows/ci.yml` con Ubuntu 24.04 y Python 3.12.
El job de systemd es independiente y falla si no hay manager systemd o el preflight
no puede alcanzarlo; ejecuta pytest con root para evitar que un skip pase inadvertido.
Los markers `integration`, `systemd` y `docker` ya están definidos. En cada
entrega Luna reporta conteos passed/failed/skipped; cero tests no
valida nada. Subir a CI sólo fixtures saneadas; nunca artifacts de scan real por
defecto. Linux RHEL sólo se declara probado después de una ejecución real, con
versión de psutil y sistema registradas.

## Laboratorios opcionales y sus límites

| Entorno | Qué valida | Qué no demuestra |
|---|---|---|
| Linux local / WSL2 | psutil, procfs visible, socket del usuario, output | servicios de otro host; systemd si no está habilitado |
| Contenedor Ubuntu/RHEL-compatible | ausencia systemd, namespaces, instalación | equivalencia con RHEL real o visibilidad del host |
| VM Ubuntu 24.04 o RHEL 9 de acceso legítimo | systemd y distro real | paridad con entornos corporativos |
| Compose bajo demanda | listeners publicados y separación de namespaces | inventario interno de todos los contenedores desde el host |

No se necesita Compose para aceptar 0.1. Si se usa después: Nginx (~64 MiB), una
app stdlib (~96 MiB), PostgreSQL (~256 MiB) y resto del presupuesto para runtime;
límites totales objetivo <=768 MiB, medir RSS real, imágenes por digest y arranque
bajo demanda. Credenciales sólo efímeras de laboratorio, nunca exportadas en scan.
Publicar puertos únicamente en 127.0.0.1; base de datos sin puerto host. Sin
privileged, host PID o montar docker.sock. `compose down` después de probar.

Dentro de cada contenedor sólo se observan sus namespaces. Desde WSL/host puede
haber proxy/NAT sin PID del proceso interno; eso es resultado limitado correcto.
0.1 no debe atribuir un listener del proxy a PostgreSQL. Una VM systemd opcional
con 1–2 GiB se ejecuta sola y se apaga; con 5 GiB libres no mantener varios labs.

## Medición y publicación

Medir duración monotónica, peak RSS y tamaño JSON en fixture de 1.000 procesos,
registrar máquina y versión. No usar CI compartida para afirmar SLA. Para 0.2,
comparar before/after conocido (unidad/listener agregado, detenido, permisos
reducidos) y asegurar not_comparable cuando cobertura cambia. No drift de memoria
libre ni PID. Para Docker futuro, socket inaccesible no equivale a cero containers.
