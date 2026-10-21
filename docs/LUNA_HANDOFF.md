# Handoff operativo para Luna

## Estado y siguiente tarea exacta

T00–T11 ya están implementadas: bootstrap, schema/validación del snapshot, runner,
supervisor de workers, collectors host, procesos, sockets, systemd y reglas puras de
assessment, reporting JSON seguro, integración CLI, CI y documentación de uso.
La única validación pendiente es **C14** en un host de laboratorio con manager
systemd real; este entorno no lo proporciona. Para esa validación, lee la matriz C14
y ejecuta sólo la unidad temporal aislada descrita allí. Para cualquier cambio,
consulta [brief](PROJECT_BRIEF.md), [MVP](MVP_SPEC.md), [contrato](DATA_CONTRACT.md) y
[plan](IMPLEMENTATION_PLAN.md). Inspecciona Git status e instrucciones locales.

El entorno usa Python 3.12, uv y lock congelado. Ejecuta `export
UV_CACHE_DIR=/tmp/uv-infralens-cache UV_LINK_MODE=copy`, `uv sync --frozen --extra dev`
y verifica con pytest/Ruff/build. T03–T11 están probadas en aislamiento y el CLI
produce snapshots reales locales; C14 real sigue sin verificarse.

## Orden restante

No hay otra implementación pendiente en el MVP base. Termina la comprobación de C14
en un entorno que cumpla sus requisitos; no implementes
transportes o Docker por adelantado. No solicites confirmación para decisiones ya
resueltas en estos documentos.

## Convenciones

- Python tipado en interfaces, pathlib, stdlib cuando basta; módulos pequeños,
  snake_case, Ruff py312. Comentarios sobre invariantes, no traducción del código.
- Modelos y excepciones explícitos; capturar errores esperados cerca de su origen.
  Captura genérica sólo en frontera del worker con error saneado.
- UTC para informes; reloj monotónico para deadlines. Nunca float NaN en JSON.
- Funciones puras para normalización/reglas; inyección de proveedores para tests.
- Strings de CLI en inglés para facilitar uso open source; documentación en español
  inicialmente. Códigos estables, tests de comportamiento sin acoplar a redacción.
- Sin herencia/plugins genéricos, shell=True, sudo automático ni comandos remotos.
- No listar argv/env/cwd de procesos, ni leer secretos o configs completas.
- Snapshot sensible: no commitearlo, no upload de CI, modo 0600 y advertencia al usuario.

## Verificación en cada entrega

Ejecutar pruebas de la tarea y dependencias afectadas; registrar comando, versión,
conteos y resultado. Una vez disponibles: Ruff, unitarias, integración Linux no root,
build e instalación de wheel externa. No declarar validado un comando futuro.
Fixtures systemd no equivalen a Linux systemd real; no afirmar RHEL/WSL probados
si no se ejecutaron allí. Para sockets usar puerto efímero controlado, no puertos
supuestos de servicios presentes. No ejecutar scans en infraestructura empresarial.

Gate final A1–A9 y matriz C01–C15 del test strategy, con requisitos de capacidad
separados. Reportar limitaciones reales, sin cambiar asserts para pasar. Si falla
systemd real, distinguir fallo de entorno de defecto de collector; no silenciarlo.

## No desarrollar todavía

Diff, Docker API, SSH, inventario YAML, Nginx parsers, mapas distribuidos, HTML,
SQLite, web, SaaS, vulnerabilidades, scoring de madurez, IA, remediación o monitoring.
El laboratorio Compose es opcional futuro: no prerequisite de desarrollo.

## Cuándo detenerse y pedir una decisión

Detener sólo el componente afectado si: una fuente requiere leer secretos o cambiar
estado; hace falta root obligatorio; un límite no puede garantizarse; cambiaría
semántica/versionado del contrato; hay identidad ambigua que produciría vínculos
engañosos; se necesita nueva dependencia de runtime fuera de las elegidas; no existe
prueba razonable de un comportamiento requerido. Documentar evidencia y dos
alternativas con su coste. Continuar tareas independientes. Un permiso denegado
normal es dato del scan, no motivo para pedir elevación.

## Contexto de entorno y alcance

Las tareas cloud ya están aisladas. Usa el checkout existente en
`/workspace/InfraLens`; no crees worktrees salvo petición explícita. Python 3.12,
uv y dependencias congeladas están disponibles. Los checks T00–T11 pasan; el
commit actual está en `main` y el borrador cloud guarda esa referencia. No hay
servicio persistente que arrancar ni credenciales necesarias para el flujo local.
El usuario autorizó commits revisables y push a `origin/main` al terminar cada tarea
validada; no publicar paquetes ni el entorno cloud sin una petición aparte.

Antes de cambiar código en una tarea futura, verifica las instrucciones vigentes.
Si la tarea sigue siendo exclusivamente onboarding, conserva fuentes/manifiestos/
lockfiles; la implementación requiere la tarea de desarrollo autorizada por usuario.
