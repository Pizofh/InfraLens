# Decisiones técnicas y alternativas

Estado: decisiones adoptadas para el diseño 0.1, pendientes de validar mediante
implementación. Fuentes consultadas el 2026-10-21. Ninguna versión upstream citada
implica pin de dependencia. T00 resolvió las dependencias runtime y de desarrollo,
que están fijadas en `pyproject.toml` y `uv.lock`; Luna debe revisarlas antes de
proponer una dependencia nueva.

## D01 — Flujo local antes de SSH; diff antes de multihost

Alternativa: comenzar por inventario SSH y mapas. Decisión: 0.1 local, 0.2 diff,
Docker 0.3 condicionado, después SSH. Un host permite verificar cambios con oráculos
simples. SSH añade autenticación, identidad remota y compatibilidad Python; mapas
añaden NAT, balanceadores, tráfico efímero y falsos vínculos. Se conserva un formato
transportable, sin framework de transportes ni clases remotas vacías.

## D02 — Python 3.12, argparse y psutil

Argparse y salida textual stdlib bastan para una CLI de un comando; Typer y Rich
no aportan suficiente valor inicial. psutil sí evita reimplementar procfs y varias
APIs de recursos/procesos. Aunque ofrece APIs de escritura, InfraLens usará sólo
una allowlist de lecturas. No asumir que sus permisos garantizan inventario completo.
Pydantic 2 se justifica para contratos tipados, uniones y schema generado; dataclasses
requeriría construir validación equivalente. Sin Jinja2 hasta existir informe HTML.

Runtime: psutil y Pydantic 2. Desarrollo: pytest, Ruff, build y backend de packaging
ligero (setuptools). Sin framework web ni dependencias Docker/SSH. `requires-python`
>=3.12; target Ruff py312. Lock de entorno dev revisado, instalación frozen en CI;
metadata de librería usa rangos compatibles, no confundir ambos mecanismos.
uv disponible puede administrar lock, pero no será dependencia de runtime.

## D03 — Evidencia y cobertura independientes

Alternativa descartada: un enum que mezcle inferred y permission_denied. Una
lectura válida puede coexistir con acceso parcial. Separar estado, cobertura y
claim permite decir qué se sabe sin afirmar salud global. Sin confidence=0.87:
no hay calibración que justifique probabilidades numéricas.

## D04 — Relación no equivale a dependencia

En 0.1 sólo vínculos observables de pertenencia socket/proceso y MainPID. Un PID
es reutilizable, por eso verificar create_time y temporalidad. Puerto 5432 no prueba
PostgreSQL y una conexión no prueba dependencia funcional. Correlación de configs
se excluye hasta disponer de parsers explícitos y política de secretos; evitar
regex sobre archivos arbitrarios.

## D05 — systemctl como capacidad opcional

Comparar subprocess con D-Bus Python: systemctl ya existe en los sistemas objetivo
y evita una dependencia nativa adicional. Consultar propiedades allowlist con
LC_ALL=C, sin pager ni comandos mutantes. Salidas de lista requieren fixtures,
las unidades cargadas no son censo de unit files. Sin systemd no falla el producto;
con systemd anunciado pero bus fallido se registra collection_error. RHEL 9 usa
versiones de systemd distintas a Ubuntu 24.04: validar en ambas antes de afirmar
paridad. No depender de JSON de systemctl disponible sólo en versiones recientes.

## D06 — JSON privado y snapshots offline

Alternativas: SQLite o backend. JSON facilita revisión y distribución sin servicios.
Coste: tamaño acotado y sin consultas históricas complejas. IDs locales y scope_id
explícito; sin fingerprint host secreto. Reportes pueden revelar topología y usuarios:
modo 0600, revisión humana y sin upload. No prometer exportación anonimizada.

## D07 — Docker y configuración fuera del MVP

Docker API expone por defecto más datos de los necesarios, incluido entorno en
inspect; acceso al socket es privilegiado y read-only es una política del cliente,
no restricción real del socket. Futuro: flag explícito, endpoint Unix local fijo,
proyección de campos permitidos, sin config/env/labels arbitrarios, sin docker group
automático. No requiere habilitarlo ahora. No añadir Docker SDK hasta ese alcance.

## D08 — Presupuesto acotado y pruebas pequeñas

Workers por colector aseguran terminación; aceptamos el coste de spawn y un pipe
acotado en vez de threads no cancelables. No llevar el MVP a concurrencia agresiva.
Tests usan sockets efímeros y fixtures; Compose y VM son jobs opcionales de capacidad.
Dos reglas simples sustituyen una calificación vaga de madurez operacional.

## D09 — Evidencia de metadatos del host

El objeto `Snapshot.host` no es una entidad normalizada, pero sus campos observados
necesitan procedencia. `Evidence.subject_id="host"` referencia ese objeto; la
validación compara sus `fields` con `Snapshot.host` y exige que la evidencia pertenezca
al collector `host`. Esto agrega semántica al identificador existente sin cambiar la
forma JSON del sobre ni inventar una entidad host duplicada. Los IDs `e:N` de cada
worker son locales y el orquestador los reenumera al ensamblar un snapshot.

## D10 — Lectura compatible sin relajar el productor

El productor conserva `extra=forbid`. El lector 1.x conserva el JSON original en
`SnapshotDocument.raw_data`, elimina extensiones aditivas sólo de la vista normalizada
que usa el código y valida los campos conocidos con los mismos modelos estrictos.
Sólo se acepta el major 1; los valores críticos desconocidos (kinds, enums y tipos)
fallan de forma cerrada. Un major futuro exige negociación explícita. El límite de
16 MiB, claves JSON duplicadas y números no finitos se rechazan para evitar lecturas
ambiguas o sin cota. Consecuencia: consumidores pueden retener datos que InfraLens
aún no entiende sin incluirlos inadvertidamente en una comparación.

## D11 — Preflight conservador para comparación

Antes de comparar, exigir `scope_origin=operator`, `scope_id` idéntico, el mismo
schema major y contexto de colección conocido e idéntico: uid/euid y namespaces
pid/net/mnt. Si falta o difiere cualquier valor, rechazar el diff global y devolver
códigos estables, sin nombres ni datos del host. `boot_id` distinto no bloquea por sí
solo: permite comparar el mismo scope tras un reinicio. No hay override en 0.2 hasta
que existan pruebas que justifiquen cómo conservar la advertencia.

## D12 — Identidad de servicio en snapshots

El nombre de unidad systemd es la clave natural entre scans. IDs de entidad son
locales y `main_pid`, `active_state` y `sub_state` son valores que pueden cambiar sin
que cambie la identidad del servicio. Si una entrada tiene el mismo nombre duplicado
en cualquier lado, el matching la deja ambigua; no escoge una instancia ni la expone
como alta o baja. La cobertura del colector y la clasificación final quedan para D05.

## Capacidades existentes y posición de InfraLens

| Herramienta | Capacidad real relevante | Lo que no resuelve automáticamente | Decisión |
|---|---|---|---|
| Ansible Facts / setup | subsets de datos de host, red, hardware; filtros y timeout; service_facts/package_facts son módulos separados | Evidencia por vínculo, topología funcional o comparación prudente definida aquí | No depender de Ansible en 0.1; considerar importador facts opcional |
| osquery | Tablas consultables con SQL; systemd_units, procesos y sockets según plataforma/permisos | Consultar tablas no demuestra dependencias funcionales; deployment y privilegios propios | No replicar motor SQL; valorar importación de consultas allowlist cuando haya usuarios |
| Lynis | Auditoría de seguridad/hardening de Unix con pruebas, advertencias y sugerencias | Inventario neutral con este contrato y causalidad de aplicaciones | No copiar un catálogo de hardening; integración offline futura si hay demanda |
| OpenSCAP | Evaluación de contenido SCAP/OVAL/XCCDF y exportación de resultados | Descubrimiento genérico de relaciones funcionales; necesita contenido aplicable | Excluir compliance/CVE del MVP; reutilizar resultados si se requiere después |
| lshw / util-linux (lsblk, lscpu) | Inventario de hardware/bloques/CPU, algunas salidas estructuradas | Servicios y relaciones entre procesos; hardware completo puede necesitar root | Preferir psutil para subset pequeño; no reimplementar inventario exhaustivo |
| NetBox | Modelo e inventario/DCIM/IPAM mantenido por operadores e integraciones | Fuente automática de verdad sobre procesos y servicios vivos | No desplegar NetBox; exportador futuro sólo con caso de uso |

No hay ventaja en crear un escáner de vulnerabilidades o motor de consultas propio.
Si tres escenarios no muestran mejora sobre Ansible Facts + scripts, mantener
InfraLens como CLI pequeña o reducir alcance en lugar de inventar plataforma.

## Fuentes y nivel de verificación

Sitios docs.ansible.com, osquery.io, cisofy.com, open-scap.org, ezix.org,
freedesktop.org, readthedocs.io y docs.docker.com devolvieron 403 del proxy en esta
sesión. No se afirma haber leído su documentación web actual. Se consultaron
fuentes primarias alternativas en GitHub (HTTP 200 con TLS validado):

- [Ansible setup, devel](https://github.com/ansible/ansible/blob/devel/lib/ansible/modules/setup.py): documentación embebida de gather_subset, filter y gather_timeout.
- [osquery systemd_units](https://github.com/osquery/osquery/blob/master/specs/linux/systemd_units.table): columnas de estados y procedencia de unidades.
- [Lynis README](https://github.com/CISOfy/lynis/blob/master/README): alcance de auditoría de seguridad y sistemas.
- [OpenSCAP README maint-1.3](https://github.com/OpenSCAP/openscap/blob/maint-1.3/README.md): uso de oscap y contenido OVAL/XCCDF.
- [psutil README](https://github.com/giampaolo/psutil/blob/master/README.rst): recursos, procesos y sockets; no asumir por ello visibilidad completa.
- [Moby API Swagger](https://github.com/moby/moby/blob/master/api/swagger.yaml): schemas de ContainerInspect y configuración; motiva minimizar datos.

Fuentes móviles de rama: no son evidencia de una release concreta ni garantía de
compatibilidad. La tabla lshw/util-linux y NetBox es orientación de alcance basada
en capacidades conocidas, sin verificación actual de versión en esta sesión.
Antes de integrar esas herramientas consultar sus documentos oficiales. No hay
ninguna dependencia de ellas en 0.1.

Referencias que Luna debe verificar contra versiones resueltas: documentación de
psutil net_connections/AccessDenied, Pydantic 2 model_json_schema, argparse,
systemctl de la distribución y seguridad del socket Docker si se aborda 0.3.
No abrir la red a dominios bloqueados para esta etapa: GitHub permitió investigar
lo necesario. No se han instalado o ejecutado las herramientas comparadas.

## Riesgos y disparadores de revisión

| Riesgo | Tratamiento y disparador |
|---|---|
| psutil omite información silenciosamente | Cobertura parcial sin root y fixtures; no declarar completitud global |
| Inventario cambia durante scan | Tiempos por colector, PID+create_time, omitir vínculos inciertos |
| Scope equivocado en diff | Exigir UUID de operador y namespaces conocidos/comparables; override futuro explícito |
| Fuga de información | Allowlist de campos, canarios, modo privado; ningún parser genérico |
| Spawn/límites cuestan más que presupuesto | Medir en T03/T10; ajustar presupuesto documentado, no quitar límites |
| RHEL/WSL no disponibles | Etiquetar no probado, sin equivalencia basada en imagen de contenedor |
| Semántica de schema cambia | Revisar contrato y fixtures antes de colectores; major si rompe lectura |
