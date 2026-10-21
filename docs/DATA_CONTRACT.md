# Contrato de snapshot 1.0.0

Contrato implementado por los modelos productores de `src/infralens/models.py`.
El JSON Schema versionado está en [`schemas/snapshot-1.0.0.schema.json`](../schemas/snapshot-1.0.0.schema.json)
y se regenera con `uv run --frozen python scripts/export_schema.py`. El schema
cubre tipos, enums, campos requeridos y la unión discriminada; las referencias entre
registros e invariantes condicionales se validan además en Pydantic. La suite valida
un fixture parcial, otro con relación socket/proceso comprobada y un caso con PID
desconocido sin relación inventada.

JSON UTF-8, sin NaN/Infinity, fechas RFC3339 UTC con Z, bytes enteros no negativos,
porcentajes derivados y no almacenados como fuente autoritativa.

## Separar conocimiento de ejecución

No mezclar observación con estado del colector en un solo enum.

| Eje | Valores | Semántica |
|---|---|---|
| Afirmación | observed, inferred, unknown | Lectura directa; deducción con regla; información insuficiente |
| Ejecución de colector | ok, unsupported, permission_denied, collection_error, skipped | Finalizó; falta capacidad; denegado; falló/timeout; no intentado |
| Cobertura | complete, partial, none | Dentro del ámbito declarado, nunca de toda la infraestructura |
| Evaluación de regla | triggered, not_triggered, not_evaluable | Condición verdadera; falsa con datos suficientes; sin datos suficientes |

Un colector puede status=permission_denied y coverage=partial si obtuvo algunos
objetos. status=ok con coverage=partial expresa truncamiento, carreras o visibilidad
no garantizada. unsupported/skipped requieren none y cero objetos. collection_error
puede tener partial o none. ok+none no es válido. Permission_denied exige al menos
un error de permiso. Complete exige ok, sin truncamiento ni errores de cobertura;
puede contener cero objetos, y no elimina las limitaciones del método.

Si coexisten errores, prioridad collection_error > permission_denied > ok; todos
se conservan en errors. Un timeout global produce skipped en colectores no iniciados.
Errores de colección no son hallazgos operativos del host.

## Sobre y campos

| Campo | Tipo y obligación |
|---|---|
| schema_version | literal 1.0.0; SemVer del formato, distinto de tool_version |
| tool_version | versión instalada de InfraLens |
| scan_id | UUID nuevo por ejecución |
| scope_id | UUID del operador o generado; scope_origin operator/generated |
| started_at, finished_at | UTC; finished >= started |
| host | OS id/version, kernel, hostname opcional, boot_id opcional; campo null con limitación |
| context | uid, euid, namespaces pid/net/mnt opcionales, context limitations |
| collectors | lista, una entrada por host/processes/sockets/systemd incluso fallidos |
| entities | unión discriminada por kind; objetos de datos normalizados |
| evidence | muestras estructuradas saneadas; no raw stdout |
| relations | vínculos entre entidades con evidencia y confianza |
| assessment | evaluaciones por regla/sujeto; estado y finding_id opcional |
| findings | hallazgos con regla, sujeto, evidencia y revisión sugerida |
| limitations | códigos y mensajes propios globales |

No incluir una etiqueta global healthy. El consumidor calcula integridad a partir
de colectores y evaluaciones. No usar warnings textuales como sustituto de estados.

Cada colector: id, status, coverage, scope (texto fijo del método), started_at,
finished_at, entity_ids, evidence_ids, errors[], limitations[], truncated boolean.
Cada error: code enum (`permission_denied`, `timeout`, `command_failed`,
`parse_error`, `io_error`, `worker_error`, `global_deadline`), operation allowlist,
message saneado; errno/exit_code opcionales. Sin stderr ni excepción cruda.
Limitación: code estable y message de plantilla; subject_id opcional.

Cada entidad: id único dentro del snapshot (`kind:ordinal`), kind, attributes,
evidence_ids no vacíos. Tipos 0.1:

| kind | attributes requeridos (null sólo donde se indica) |
|---|---|
| host_resources | cpu_logical:int|null, memory_total_bytes:int|null, memory_available_bytes:int|null |
| filesystem | device:str, mountpoint:str, fs_type:str, total_bytes:int|null, used_bytes:int|null, free_bytes:int|null |
| interface | name:str, is_up:bool|null, addresses:[{family:ipv4/ipv6,address:str,prefix_length:int|null}] |
| process | pid:int>0, started_at:timestamp|null, name:str|null, uid:int|null |
| socket | protocol:tcp/udp, family:ipv4/ipv6, local_address:str, local_port:1..65535, state:listen/bound, pid:int|null |
| service | name:str, load_state:str, active_state:str, sub_state:str, main_pid:int|null |

main_pid=0 de systemd se normaliza a null (sin main process); no se crea proceso 0.
PID de un socket es una pista observada, no una referencia estable ni una relación
confirmada. IPs normalizadas con ipaddress; IPv6 incluye scope_id separado si existe
(zona local opcional en socket/address). No convertir wildcard IPv6 en IPv4.
Prefijos desconocidos son null. No excluir loopback o tmpfs silenciosamente: declarar
que disk_partitions(all=False) tiene su propio filtro y no es censo de mounts.
Campos nulos llevan limitación con subject_id y nombre de campo en el mensaje.

IDs de entidades y evidencia no son identidades entre snapshots. Un proceso se
identifica sólo durante el scan por pid+started_at+contexto de arranque; sin tiempo
no enlazar. Para diff: filesystem=(mountpoint,device,fs_type), servicio=name,
listener=(protocol,family,local_address,local_port,zone). No diff de procesos en 0.2.

Evidencia: id, collector_id, collected_at, source {type:api/file/command,
name:valor allowlist, locator:str opcional saneado}, subject_id, claim:observed,
fields:mapa de campos permitidos, limitations[]. Un hash de un archivo no sustituye
la evidencia ni implica que sea seguro leer ese archivo. No leer configuraciones
arbitrarias ni incluir hashes de secretos.

Relación: id, type (`owned_by`, `main_process`), from_id, to_id, claim,
evidence_ids, rationale_code. 0.1 sólo observed con verificación temporal descrita
en arquitectura; inferred queda reservado y exige regla y explicación en una
versión posterior. Unknown no crea arista a una entidad ficticia: usar limitación
con subject_id. No representar unavailable como un host vacío observado.

Hallazgo: id, rule_id, rule_version, severity:warning, subject_id, claim:observed,
evidence_ids, message plantilla, review_action. Evaluación: rule_id, rule_version,
subject_id nullable (null sólo si no hubo sujetos observables), state,
finding_id nullable, reason_code nullable; triggered requiere finding y evidencia,
not_evaluable exige reason_code. Cada par regla/sujeto es único.

## Invariantes y compatibilidad

Referencias deben resolver dentro del snapshot; evidencia y sujeto deben coincidir.
Todos los objetos pertenecen a un colector y aparecen en su entity_ids; evidence_ids
resuelve a ese mismo colector. IDs únicos por colección. Entidades ligadas al mismo
scope, no enlaces entre scans. TCP requiere state=listen; UDP state=bound. No
números negativos; available/used/free <= total cuando total es conocido. No exigir
used+free=total: bloques reservados y semánticas de filesystem pueden diferir.

Productor valida con extra=forbid para descubrir errores. Lector 1.x acepta sólo
majors conocidos, conserva campos desconocidos aditivos y los ignora al comparar;
no descarta semántica crítica ni acepta tipos inválidos. Esquema mayor nuevo para
eliminar campos, cambiar significados o enums de control. Nuevos tipos de entidad
y enums requieren negociación de lector: no tratarlos automáticamente como adición
compatible. Fixture 1.0.0 congelado y pruebas de migración antes de 2.0.

## Ejemplo mínimo de cobertura parcial

Ejemplo reducido pero completo del sobre; sólo un filesystem es observable.
Tiempos e identificadores son sintéticos, no datos recolectados del entorno.
Los campos de host faltantes están declarados en limitaciones. Este ejemplo reducido
está cubierto por `tests/fixtures/snapshot_partial.json`; T01 ya validó el fixture,
los modelos y el schema generado. Cualquier cambio posterior al contrato debe
actualizar juntos el fixture, los modelos, el schema y sus pruebas.

```json
{
  "schema_version": "1.0.0",
  "tool_version": "0.1.0",
  "scan_id": "20ce8dac-2789-47d6-b057-80bf452c2503",
  "scope_id": "39cb65cb-a089-4208-82f7-d636cdb7bef1",
  "scope_origin": "operator",
  "started_at": "2026-10-21T14:00:00Z",
  "finished_at": "2026-10-21T14:00:01Z",
  "host": {
    "os_id": "ubuntu",
    "os_version": "24.04",
    "kernel": "6.8.0",
    "hostname": null,
    "boot_id": null
  },
  "context": {
    "uid": 1000,
    "euid": 1000,
    "namespaces": {
      "pid": null,
      "net": null,
      "mnt": null
    },
    "limitations": [
      {
        "code": "context_unavailable",
        "message": "Namespaces pid, net, mnt no disponibles en este ejemplo."
      }
    ]
  },
  "collectors": [
    {
      "id": "host",
      "status": "permission_denied",
      "coverage": "partial",
      "scope": "OS y filesystems legibles; recursos/interfaces no accesibles",
      "started_at": "2026-10-21T14:00:00Z",
      "finished_at": "2026-10-21T14:00:01Z",
      "entity_ids": [
        "filesystem:1"
      ],
      "evidence_ids": [
        "e:1"
      ],
      "errors": [
        {
          "code": "permission_denied",
          "operation": "read_host_resources",
          "message": "Acceso limitado en el escenario sintético."
        }
      ],
      "limitations": [],
      "truncated": false
    },
    {
      "id": "processes",
      "status": "permission_denied",
      "coverage": "none",
      "scope": "Procesos visibles al usuario",
      "started_at": "2026-10-21T14:00:00Z",
      "finished_at": "2026-10-21T14:00:01Z",
      "entity_ids": [],
      "evidence_ids": [],
      "errors": [
        {
          "code": "permission_denied",
          "operation": "process_iter",
          "message": "Acceso limitado en el escenario sintético."
        }
      ],
      "limitations": [],
      "truncated": false
    },
    {
      "id": "sockets",
      "status": "permission_denied",
      "coverage": "none",
      "scope": "Sockets TCP LISTEN y UDP bound del namespace",
      "started_at": "2026-10-21T14:00:00Z",
      "finished_at": "2026-10-21T14:00:01Z",
      "entity_ids": [],
      "evidence_ids": [],
      "errors": [
        {
          "code": "permission_denied",
          "operation": "net_connections",
          "message": "Acceso limitado en el escenario sintético."
        }
      ],
      "limitations": [],
      "truncated": false
    },
    {
      "id": "systemd",
      "status": "unsupported",
      "coverage": "none",
      "scope": "Unidades service cargadas en el system manager",
      "started_at": "2026-10-21T14:00:00Z",
      "finished_at": "2026-10-21T14:00:01Z",
      "entity_ids": [],
      "evidence_ids": [],
      "errors": [],
      "limitations": [
        {
          "code": "runtime_absent",
          "message": "No hay systemd operativo."
        }
      ],
      "truncated": false
    }
  ],
  "entities": [
    {
      "id": "filesystem:1",
      "kind": "filesystem",
      "attributes": {
        "device": "/dev/vda1",
        "mountpoint": "/",
        "fs_type": "ext4",
        "total_bytes": 10737418240,
        "used_bytes": 10200547328,
        "free_bytes": 536870912
      },
      "evidence_ids": [
        "e:1"
      ]
    }
  ],
  "evidence": [
    {
      "id": "e:1",
      "collector_id": "host",
      "collected_at": "2026-10-21T14:00:00Z",
      "source": {
        "type": "api",
        "name": "psutil.disk_usage",
        "locator": "/"
      },
      "subject_id": "filesystem:1",
      "claim": "observed",
      "fields": {
        "total_bytes": 10737418240,
        "used_bytes": 10200547328,
        "free_bytes": 536870912
      },
      "limitations": []
    }
  ],
  "relations": [],
  "assessment": [
    {
      "rule_id": "FS_USAGE_HIGH",
      "rule_version": "1.0.0",
      "subject_id": "filesystem:1",
      "state": "triggered",
      "finding_id": "f:1",
      "reason_code": null
    },
    {
      "rule_id": "SYSTEMD_FAILED",
      "rule_version": "1.0.0",
      "subject_id": null,
      "state": "not_evaluable",
      "finding_id": null,
      "reason_code": "collector_unsupported"
    }
  ],
  "findings": [
    {
      "id": "f:1",
      "rule_id": "FS_USAGE_HIGH",
      "rule_version": "1.0.0",
      "severity": "warning",
      "subject_id": "filesystem:1",
      "claim": "observed",
      "evidence_ids": [
        "e:1"
      ],
      "message": "Uso de /: 95% en esta muestra.",
      "review_action": "Revisar crecimiento y capacidad; no borrar datos automáticamente."
    }
  ],
  "limitations": [
    {
      "code": "host_metadata_partial",
      "message": "hostname y boot_id no disponibles; recursos e interfaces fuera de cobertura en este ejemplo."
    }
  ]
}
```

Sin servicios observables no hay prueba de ausencia: systemd es unsupported.
Sin visibilidad de sockets la regla de puertos (inexistente en 0.1) no podría afirmar
seguridad. Los fixtures `snapshot_process_socket.json` y `snapshot_unknown_owner.json` cubren
la relación verificada y el PID desconocido sin arista fabricada, respectivamente.
