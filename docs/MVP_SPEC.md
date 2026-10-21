# Especificación normativa MVP 0.1

Los MUST de recolección de esta especificación son criterios de aceptación
pendientes; T00–T10 implementan CLI, contrato, runner, supervisor, collectors aislados
de OS, recursos, contexto, filesystems, interfaces, procesos, sockets y servicios
systemd, reglas puras de assessment, reporting seguro e integración del comando
`scan`. Plataforma objetivo Linux
con Python 3.12; primera validación Ubuntu 24.04. RHEL 9 y WSL2 requieren pruebas
explícitas.

## CLI definitiva de esta versión

```bash
infralens --version
infralens scan --local --output ./snapshot.json
infralens scan --local --output ./snapshot.json --scope-id 39cb65cb-a089-4208-82f7-d636cdb7bef1
infralens scan --local --output ./snapshot.json --overwrite --fail-on-partial
```

`--local` obligatorio: hace explícito el objetivo; no se acepta host ni inventario.
`--output` obligatorio, sólo archivo local, no stdout ni URL; no crea directorios.
`--scope-id` UUID opcional: identificador gestionado por el operador para scans de
un mismo host/ámbito; si se omite se genera uno nuevo y se advierte que no habilita
comparación entre ejecuciones. No es prueba de identidad ni autenticación.
No flags de root, sudo, shell, comandos arbitrarios ni lectura de configuraciones.
Presupuestos de tiempo y tamaño fijos en 0.1; no añadir flags prematuros.

Resumen en stdout: plataforma, alcance, tiempos, contadores por colector, cobertura,
hallazgos con evidencia y advertencia de información sensible. Diagnósticos de CLI
en stderr. No colocar JSON o comandos internos completos en el resumen. `--version`
y `--help` funcionan sin lanzar colectores. Orden estable de listas por clave natural.

## Códigos de salida

| Código | Significado |
|---|---|
| 0 | Snapshot válido persistido, incluso si cobertura parcial/unsupported; hallazgos no cambian código |
| 1 | Fallo fatal: no se pudo obtener contexto mínimo Linux o escribir/validar snapshot |
| 2 | Uso inválido, plataforma no Linux, ruta inválida o archivo existente sin --overwrite |
| 3 | Con --fail-on-partial: snapshot persistido pero algún colector no completó su ámbito solicitado |
| 130 | Interrupción por usuario; no publicar snapshot incompleto |

Unsupported systemd también activa código 3 en modo estricto. El modo normal no
oculta el estado: siempre imprime cobertura. Una regla no evaluable no es un fallo
del proceso si los colectores cumplieron su ámbito; se declara en assessment.

## Comportamiento obligatorio

- OS, recursos, mounts e interfaces según la allowlist de arquitectura. Un campo
  desconocido es null con limitación asociada; cero es un valor, no desconocimiento.
- Procesos y sockets efímeros toleran desaparición; inventario de mínimo privilegio.
- TCP LISTEN y UDP bound: UDP no se etiqueta LISTEN ni servicio demostrado.
- Servicio no cargado queda fuera del ámbito de list-units; no inferir disabled.
- Docker no se consulta. No se lee `docker inspect`, config de Nginx ni credenciales.
- Todos los colectores se intentan salvo deadline global o contexto mínimo fatal;
  los restantes se registran skipped, nunca desaparecen del informe.
- Incluir límites, truncamiento, permisos y fuentes por sección. Colección vacía sólo
  significa ausencia dentro del ámbito cuando la cobertura fue completa.
- Sin descargas, instalaciones, cambios de permisos del sistema ni acceso remoto.

## Hallazgos exactos

| ID | Condición | Evidencia y límites | Revisión sugerida |
|---|---|---|---|
| FS_USAGE_HIGH | total_bytes >0 y `used_bytes * 100 >= total_bytes * 90` | evidencia disk_usage del mismo mount; evaluación independiente por filesystem, incluso con cobertura parcial en otros | Revisar crecimiento y capacidad; no borrar datos |
| SYSTEMD_FAILED | unidad cargada con ActiveState=failed | muestra de propiedades y unidad; no implica causa raíz | Revisar logs y contexto manualmente |

Ambos severity=warning, sin score agregado. Una regla devuelve not_evaluable cuando
no existe dato suficiente; retorna not_triggered sólo para objetos evaluados que
no cumplen la condición. Para filesystem total=0, not_evaluable. No usar redondeo
visual para comparar umbral. Un root filesystem ausente no se considera sano.
No añadir alertas por puertos abiertos ni inferir vulnerabilidades.

## Persistencia segura

Máximo JSON final 16 MiB, strings <=4.096 caracteres y captura de comando <=1 MiB;
al alcanzar límites el colector queda partial y records se recortan en orden estable.
Si aun así la serialización excede 16 MiB, fallo fatal explícito; no JSON truncado.
La captura detecta exceso durante lectura, sin almacenar salida ilimitada en memoria.

Crear temporal 0600 en el directorio destino y validar antes de publicar. Sin
`--overwrite`, publicación con creación exclusiva/no-replace; una carrera no puede
sobrescribir otro archivo. Rechazar symlink como destino. Con overwrite usar rename
atómico sobre archivo regular, validar directorio y limpiar temporal ante errores.
No truncar el archivo anterior hasta completar validación. Directorios de destino
son administrados por el usuario: no soportar directorios compartidos hostiles en
0.1. Se documenta este límite; no afirmar que lstat resuelve todas las carreras.

## Aceptación funcional

A1: `--help` y `--version` sin llamadas al sistema de colección.
A2: scan no root en Linux produce contrato válido y conteos consistentes.
A3: listener efímero controlado aparece por IP/puerto y luego deja de observarse.
A4: sin systemd se reporta unsupported; con bus inaccesible error/denied.
A5: acceso denegado, timeout y truncamiento conservan otros resultados.
A6: fixtures con secretos y ANSI no filtran contenido prohibido.
A7: reglas y referencias coinciden exactamente con evidencias; falso positivo cero
sobre fixtures negativos definidos, sin generalizar a entornos desconocidos.
A8: escritura, overwrite, permisos, interrupción y códigos cumplen lo anterior.
A9: worker bloqueado termina dentro de deadline + limpieza y sin hijos huérfanos.
