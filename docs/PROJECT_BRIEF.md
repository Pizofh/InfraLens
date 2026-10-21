# InfraLens: propósito y alcance

Estado: MVP en construcción. T00–T03 están implementados: CLI inicial, modelos/schema
de snapshots, runner acotado y supervisor de workers. El comando `scan` todavía es un
placeholder; no existen colectores ni el flujo de inspección. Fecha inicial del
diseño: 2026-10-21.

## Problema y usuario

Un ingeniero recibe un Linux desconocido y necesita reconstruir qué está ejecutándose,
qué puede observar con su usuario y qué merece revisión. Las salidas de comandos
sueltos pierden contexto, evidencia y limitaciones. InfraLens organizará una inspección
puntual, local, explícita y reproducible. No promete un inventario completo del host.

Usuario inicial: administrador Linux o ingeniero DevOps que inspecciona su propio
laboratorio autorizado. No ejecutar inicialmente en sistemas corporativos reales.
El proyecto es independiente de MMM y carece de demanda comercial validada.

## Valor que se puede comprobar

Un snapshot JSON versionado reúne recursos, procesos, servicios y sockets; conserva
procedencia, errores y cobertura. Un resumen identifica hallazgos concretos y explica
qué no se pudo determinar. Dos snapshots comparables permiten revisar cambios
estables sin confundir ruido, permisos o namespaces con cambios de infraestructura.

La diferenciación propuesta es la explicación de evidencia y límites, junto con una
comparación prudente y portable. La recolección por sí sola ya está muy resuelta por
otras herramientas. Esta diferenciación sigue siendo una hipótesis: después del MVP,
comparar en tres escenarios de laboratorio el tiempo y exactitud frente a comandos
manuales y Ansible Facts. Registrar errores y falsos positivos; no afirmar adopción.

## Entregas y exclusiones

| Entrega | Incluye | No incluye |
|---|---|---|
| MVP 0.1 | Scan local, JSON, resumen, recursos, procesos mínimos, sockets TCP/UDP, systemd opcional, dos reglas | Docker API, SSH, diff, HTML |
| 0.2 | Comparación conservadora de snapshots del mismo ámbito | Topología multihost |
| 0.3, condicionada a utilidad | Docker explícito y acotado | Inspección completa de contenedores |
| Posterior, sin compromiso | Transporte SSH y correlación entre hosts | SaaS o agentes permanentes |

Docker se aplaza: es útil pero su socket concede capacidades equivalentes a root
en muchos despliegues. Un laboratorio puede usar Docker sin que InfraLens consulte
su API. No ejecutar Docker dentro de la herramienta en 0.1.

Sin monitoreo continuo, remediación, escaneo de redes, descubrimiento de CVE,
calificaciones de madurez, parsers de configuraciones arbitrarias, IA, base de datos,
servidor web ni integraciones cloud. No detectar roles de aplicaciones por número
de puerto. Escuchar en 0.0.0.0 no demuestra exposición a Internet.

## Criterios de éxito

1. Usuario sin root obtiene JSON válido y resumen útil en Linux con Python 3.12.
2. Un puerto TCP controlado se observa; al detenerlo desaparece en un scan nuevo.
3. Sin systemd, sin permiso o ante un proceso desaparecido, se conserva salida útil
   con cobertura parcial explícita; nunca se transforma una falla en lista vacía completa.
4. Ningún colector solicita sudo ni lee entorno, argumentos de procesos o archivos
   arbitrarios. La salida por defecto no contiene secretos de fixtures adversarios.
5. Reglas reproducibles con evidencia: filesystem >=90% y unidad systemd failed.
6. CI requerida pasa en Ubuntu; límites de contenedor, WSL y RHEL se declaran.
7. Instalación y pruebas base funcionan sin Docker, AWS ni servicios pagados.

Presupuesto inicial de validación: un proceso CLI, sin servicios persistentes,
objetivo <150 MiB RSS y <30 s por scan de laboratorio de hasta 1.000 procesos.
Son objetivos que Luna debe medir, no resultados ya obtenidos. Laboratorio Docker
opcional <768 MiB configurados en total; VM systemd opcional, una a la vez.

## Cómo leer el plan

[Especificación](MVP_SPEC.md) fija comportamiento; [contrato](DATA_CONTRACT.md)
fija semántica; [arquitectura](ARCHITECTURE.md) asigna responsabilidades;
[pruebas](TEST_STRATEGY.md) y [plan](IMPLEMENTATION_PLAN.md) hacen verificable
la entrega; [decisiones](TECHNICAL_DECISIONS.md) documenta alternativas y fuentes;
[handoff](LUNA_HANDOFF.md) indica por dónde comenzar.
