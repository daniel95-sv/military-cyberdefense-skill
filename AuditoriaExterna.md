# Auditoría técnica y de seguridad — Military Cyberdefense Skill

Requiere correcciones

Auditoría estática

Repositorio: [daniel95-sv/military-cyberdefense-skill](https://github.com/daniel95-sv/military-cyberdefense-skill?utm_source=chatgpt.com)

Fecha de revisión: 6 de noviembre de 2026.

Veredicto general: tienes una buena base conceptual y una estructura interesante, pero actualmente existen deficiencias que pueden provocar que tus herramientas declaren un proyecto seguro cuando no han podido comprobarlo correctamente.

Mi principal preocupación no es que el repositorio contenga código malicioso, sino que algunas de sus herramientas pueden generar una falsa sensación de seguridad.

He revisado el README, SKILL.md, los scripts principales en Python y PowerShell, las reglas JSON, las plantillas Docker, Cloudflare y el pipeline de GitHub Actions.

Una aclaración: esta es una revisión estática del código publicado. No he podido ejecutar toda la batería de pruebas, construir las imágenes Docker ni verificar el comportamiento real de Terraform y PowerShell.

# 1. ¿Qué es tu proyecto y para qué sirve?

Tu proyecto se llama Military-Grade Cyberdefense Skill (DEFCON-1).

Es una herramienta de ciberseguridad defensiva que combina tres componentes:

1. Una skill para asistentes de programación, especialmente Google Antigravity.
2. Una suite de scripts Python y PowerShell para realizar auditorías.
3. Un conjunto de reglas y plantillas para reforzar aplicaciones, infraestructura y procesos DevSecOps.

La estructura incluye análisis estático, detección de secretos, auditoría de dependencias, monitorización de integridad, comprobaciones de endpoints, plantillas de seguridad y generación de informes SARIF.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://github.com\&sz=32)

GitHub+1



Arquitectura funcional del proyecto

Google Antigravity / Asistente de IA

Interpreta las instrucciones de seguridad de SKILL.md

Motor de reglas centralizado

rules/security-rules.json — fuente única de verdad

Auditoría

Escaneo estático y dependencias

Hardening

Seguridad de aplicaciones e infraestructura

Integridad

Hashes, HMAC y detección de modificaciones

DevSecOps

CI/CD, Gitleaks y reportes SARIF

Informe de seguridad y recomendaciones

Hallazgos, medidas correctivas y nueva verificación

Es una propuesta interesante porque no se limita a proporcionar instrucciones para una IA: también incorpora herramientas ejecutables.

Sin embargo, hay una diferencia importante entre disponer de una colección de herramientas de seguridad y contar con una plataforma capaz de garantizar la seguridad de un sistema.

Actualmente tu proyecto pertenece más a la primera categoría.

# 2. Hallazgos importantes de la auditoría

He identificado los siguientes problemas, ordenados por su impacto.

## Hallazgo 1. El auditor de dependencias puede declarar seguridad cuando falla la conexión



Crítico

check-dependencies-osv.py



Este es uno de los problemas más importantes.

Tu script consulta la API de Google OSV para comprobar vulnerabilidades conocidas de las dependencias.

El problema está en el tratamiento de errores:

- Cuando la consulta falla, captura la excepción.
- Imprime una advertencia.
- Devuelve una lista vacía.
- El proceso principal interpreta esa lista como si no hubiera vulnerabilidades.
- Finalmente puede mostrar `DEFCON-5 (COMPLIANT)` y devolver código de salida 0.

Por tanto, una interrupción de Internet o de OSV puede producir un falso resultado de seguridad.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



Corrección necesaria:

Diferenciar tres estados:

| Estado                                   | Resultado             |
| ---------------------------------------- | --------------------- |
| Escaneo completado, sin vulnerabilidades | Aprobado              |
| Escaneo completado, con vulnerabilidades | Fallido               |
| Escaneo incompleto o API inaccesible     | Error / No verificado |

Una auditoría que no pudo completarse nunca debe declarar que el proyecto está limpio.

## Hallazgo 2. El escáner puede omitir archivos `.env`



Crítico

check-security-baseline.py



He encontrado un problema relacionado con el reconocimiento de extensiones.

El escáner obtiene la extensión utilizando:

```
_, ext = os.path.splitext(file_path)
```

Posteriormente compara la extensión con las extensiones permitidas por cada regla.

El inconveniente es que Python interpreta los archivos ocultos de esta manera:

| Archivo       | Extensión obtenida |
| ------------- | ------------------ |
| `.env`        | Vacía              |
| `.env.local`  | `.local`           |
| `secrets.env` | `.env`             |

Esto significa que los archivos `.env` y `.env.local` pueden quedar fuera de las reglas que pretenden comprobar sus secretos, aunque `.env` aparezca expresamente en algunas listas de extensiones.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



También encontré que el escáner excluye directorios como `rules` y `tests`, además de excluir archivos cuyo nombre empieza por `check-` o `patch-`.

Estas exclusiones pueden dejar fuera información relevante de una auditoría.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



Corrección necesaria:

Implementar reconocimiento específico de archivos especiales, incluyendo:

- `.env`
- `.env.local`
- `.env.production`
- `.npmrc`
- `.pypirc`
- `.htpasswd`
- Archivos de configuración sin extensión.
- Certificados y archivos de claves privadas.

Las exclusiones deben ser configurables y no aplicarse indiscriminadamente.

## Hallazgo 3. El escáner estático depende de expresiones regulares



Alto

check-security-baseline.py



Actualmente se utilizan reglas regex que buscan patrones concretos línea por línea.

Esto funciona para determinadas comprobaciones, como localizar:

- Claves API.
- Claves privadas.
- Uso de MD5.
- Uso de `eval()`.
- Configuraciones Docker peligrosas.
- Determinados patrones de inyección.

Pero tiene limitaciones importantes.

Por ejemplo, puede detectar una utilización de `innerHTML`, pero no necesariamente determinar si el contenido proviene de una fuente controlada por un atacante.

Tampoco puede analizar correctamente todos los flujos de datos entre funciones, módulos y servicios.

El código realiza búsquedas individuales por línea y silencia excepciones de lectura.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



Mi recomendación: evolucionar hacia un motor híbrido:

- Reglas regex para detecciones rápidas.
- AST para JavaScript, TypeScript y Python.
- Análisis de flujo de datos.
- Detección de secretos especializada.
- Análisis de configuraciones IaC.
- Integración con herramientas de análisis de seguridad reconocidas.

Puedes mantener tu motor actual como primera capa, pero no debería ser la única.

## Hallazgo 4. El verificador SSOT no comprueba realmente el 100 % de la paridad



Crítico

sync-and-validate.py



La idea de utilizar `security-rules.json` como fuente única de verdad es excelente.

Sin embargo, encontré problemas en cómo verificas la sincronización.

Problema A: cabeceras HTTP

El verificador crea un mapa con los valores recomendados, pero comprueba principalmente que existan los nombres de las cabeceras.

No verifica que sus valores coincidan realmente con los valores establecidos en el SSOT. Además, el modo `--sync` incorpora las cabeceras faltantes, pero no corrige automáticamente los valores incorrectos existentes.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



Problema B: Cloudflare WAF

Encontré una diferencia concreta:

En el JSON, la regla de reconocimiento bloquea:

- `/phpmyadmin`
- `/.env`
- `/.git`
- `/wp-login.php`

En Terraform también se incluye:

\- `/xmlrpc.php`

Además, Terraform contempla `/api/v1/auth/login` en la regla de limitación, mientras que el JSON tiene otra lista de endpoints.

Sin embargo, el comprobador se concentra en los parámetros numéricos de limitación y no compara completamente las expresiones, acciones y reglas.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+2



Problema C: Gitleaks

La comprobación se basa en buscar determinadas cadenas dentro del archivo de configuración, no en verificar la equivalencia de los patrones y su comportamiento.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub



Esto puede generar un resultado de sincronización correcta cuando las configuraciones no son realmente equivalentes.

Corrección necesaria: generar las configuraciones derivadas desde el SSOT y verificar su equivalencia semántica, no solamente la existencia de determinadas cadenas.

## Hallazgo 5. El sistema de parcheo tiene riesgos importantes



Alto

patch-and-reverify.py



Aquí he encontrado tres aspectos que necesitan atención.

1\. Ejecución de comandos mediante shell

El código utiliza:

```
subprocess.run(cmd, shell=True)
```

El comando de pruebas puede proceder de un argumento externo.

Esto permite ejecutar comandos arbitrarios si un agente, proceso automatizado o usuario introduce una cadena no confiable.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub



No significa que el script sea malware, pero sí que requiere una protección importante.

2\. Las pruebas iniciales pueden fallar y el procedimiento continúa.

Cuando las pruebas previas fallan, el script simplemente muestra una advertencia.

No detiene el proceso.

Por tanto, no existe necesariamente una línea base funcional válida antes de modificar el código.

3\. Puede certificar cero regresiones sin ejecutar pruebas.

El parámetro `--test` es opcional. Si no se proporciona, el proceso puede llegar igualmente a imprimir:

`PATCH VALIDATED: Zero Defect + Zero Regression`.

Esto no es correcto: sin ejecutar pruebas funcionales no se puede certificar que no existan regresiones.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub



También observé que el mecanismo hace una copia de seguridad del archivo objetivo y espera que el usuario aplique manualmente el parche. No implementa por sí mismo la generación ni la aplicación automática de una corrección.

Corrección necesaria:

- Utilizar ejecución de procesos sin `shell=True`.
- Exigir que las pruebas iniciales pasen.
- No certificar regresiones cuando no se ejecutaron pruebas.
- Registrar todos los archivos afectados.
- Verificar las restauraciones.
- Incorporar un modo de simulación.
- Exigir autorización explícita antes de modificar código.

## Hallazgo 6. El auditor de endpoints necesita protección contra SSRF



Alto

check-live-endpoint.py



El auditor recibe una URL y realiza solicitudes HTTP utilizando `urllib.request.urlopen`.

No encontré una protección suficiente que impida acceder a direcciones privadas, loopback o servicios internos.

El tratamiento de direcciones locales que aparece en el código se utiliza para omitir ciertas comprobaciones DNS, no para bloquear las solicitudes HTTP anteriores.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+2



Esto puede convertirse en un problema cuando el script se ejecuta dentro de un agente autónomo o CI/CD que procesa URLs procedentes de usuarios o fuentes externas.

Escenario de riesgo: una entrada no confiable podría intentar utilizar el auditor para acceder a servicios internos de la máquina donde se está ejecutando.

Correcciones recomendadas:

- Validar estrictamente esquemas y destinos.
- Rechazar direcciones privadas, loopback y link-local por defecto.
- Resolver DNS y validar las IP obtenidas.
- Controlar cada redirección HTTP.
- Impedir que una redirección cambie a un destino no autorizado.
- Implementar una lista de dominios permitidos.
- Exigir autorización para realizar auditorías sobre dominios externos.

## Hallazgo 7. Las cabeceras HTTP se comprueban solamente por existencia



Medio-alto

check-live-endpoint.py



Actualmente, cuando el auditor encuentra una cabecera, la considera aprobada.

Por ejemplo, si encuentra `Content-Security-Policy`, muestra un resultado positivo sin comprobar si la política es realmente segura.

Esto no es suficiente.

Una política CSP puede existir y, aun así, permitir ejecuciones inseguras.

También la comprobación de `security.txt` se limita principalmente a buscar `Contact:`, sin validar integralmente el documento.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub



Corrección necesaria: comprobar contenido, directivas, valores, fechas y condiciones concretas según cada estándar.

# 3. Auditoría de las plantillas de producción

Aquí también encontré aspectos importantes.

## Dockerfile.hardened

Requiere modificaciones

Tu Dockerfile tiene buenas medidas:

- Ejecución con usuario no privilegiado.
- Separación de etapas.
- Eliminación del gestor de paquetes.
- Copia controlada de los artefactos.
- Restricción del entorno de ejecución.

Sin embargo, existe una contradicción importante.

El archivo describe la etapa final como Distroless, pero utiliza:

```
FROM node:22-alpine AS production
```

Alpine no es una imagen Distroless.

Además, las imágenes Node se utilizan sin digest SHA-256 y el propio archivo deja indicado que el pinning todavía está pendiente.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



También hay que comprobar que la aplicación realmente tenga `dist/index.js` y el endpoint `/health`, ya que la plantilla presupone ambas cosas.

Mi recomendación: utilizar una imagen de ejecución mínima apropiada, fijar los digests de todas las imágenes base y realizar análisis de la imagen resultante, no únicamente del Dockerfile.

## docker-compose.hardened.yml

Tiene buenas configuraciones, pero encontré algo que merece especial atención:

```
REDIS_URL=redis://:CHANGE_TO_COMPLEX_SECRET@redis:6379
```

También repite el mismo valor de contraseña en la configuración de Redis, su comprobación de salud y PostgreSQL.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



Son marcadores de posición, no credenciales reales, pero si alguien utiliza la plantilla sin sustituirlos, terminará desplegando con contraseñas conocidas.

Recomiendo:

- Utilizar Docker Secrets o un gestor externo de secretos.
- Eliminar los puertos publicados de Redis y PostgreSQL cuando no sean necesarios.
- Mantener únicamente la comunicación interna entre servicios.
- Añadir límites de CPU y memoria.
- Definir políticas de registro y rotación.
- Evaluar las restricciones de salida de red.

## Cloudflare WAF

La arquitectura es útil, especialmente por integrar reglas de firewall y limitación de solicitudes.

Pero necesitas resolver la diferencia entre JSON y Terraform que mencioné anteriormente.

No recomiendo aplicar las configuraciones automáticamente hasta garantizar su equivalencia.

# 4. Auditoría de GitHub Actions y DevSecOps

Mejoras necesarias

He observado decisiones acertadas en el pipeline:

- Permisos relativamente limitados.
- `persist-credentials: false`.
- Algunas acciones fijadas mediante SHA.
- Ejecución de pruebas Python.
- Escaneo de dependencias.
- Generación y publicación de reportes SARIF.

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1

Sin embargo, detecté dos problemas.

Primero: acciones externas sin fijación por SHA.

La plantilla utiliza:

```
uses: aquasecurity/trivy-action@master
```

`master` es una referencia mutable. En un pipeline de seguridad recomiendo fijar el commit exacto y verificarlo antes de actualizarlo.

También conviene fijar por SHA las acciones que actualmente utilizan etiquetas como `@v3`.

Segundo: alcance del análisis Trivy.

El pipeline utiliza:

```
scan-type: 'config'
```

Esto corresponde al análisis de configuración. No equivale a analizar todas las vulnerabilidades de los paquetes contenidos en una imagen Docker construida.

Por tanto, necesitas una etapa adicional de análisis de imágenes y vulnerabilidades de sus componentes.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub



Otra observación: el trabajo denominado `agent-skills-audit` utiliza el escáner de expresiones regulares general. No representa por sí solo un análisis semántico especializado de instrucciones y herramientas de agentes IA.

# 5. ¿Contiene virus o código malicioso?

Esta es una parte especialmente importante de tu solicitud.

Resultado de la inspección estática

No encontré código malicioso evidente en los archivos centrales examinados.

Los scripts revisados utilizan operaciones coherentes con las funciones que declara el proyecto:

- Consultas a OSV.dev.
- Solicitudes HTTP a los endpoints indicados.
- Consultas DNS mediante Google DNS-over-HTTPS.
- Lectura y cálculo de hashes de archivos.
- Ejecución de comandos de pruebas proporcionados por el operador.

No obstante, hay una distinción importante:

- No he encontrado mecanismos evidentes de robo de credenciales o exfiltración de código en los scripts principales revisados.
- Las llamadas de red identificadas parecen corresponder a las funciones documentadas.
- El uso de `shell=True` merece corrección por su capacidad de ejecutar comandos arbitrarios.
- No he realizado una ejecución dinámica completa ni un análisis antivirus de todos los archivos y dependencias.

Por tanto, no sería responsable certificar que absolutamente todo el repositorio está libre de malware.

# 6. Lo que realmente está bien construido

No todo necesita reconstruirse. Hay decisiones que conservaría.

| Componente               | Evaluación                        |
| ------------------------ | --------------------------------- |
| Organización de carpetas | Buena                             |
| SKILL.md                 | Buena base                        |
| SSOT JSON                | Muy buena arquitectura            |
| Generación SARIF         | Buena                             |
| FIM con SHA-256 y HMAC   | Buena base                        |
| Integración OSV          | Buena idea, requiere correcciones |
| Plantillas Docker        | Buen punto de partida             |
| Plantillas Cloudflare    | Buena base, falta paridad real    |
| GitHub Actions           | Buena estructura                  |
| Política SECURITY.md     | Positiva                          |
| Pruebas automatizadas    | Existe infraestructura para ellas |

Una decisión que conservaría especialmente es tu enfoque de fuente única de verdad. La idea de centralizar reglas y generar configuraciones desde ella facilita mucho el mantenimiento de un proyecto de esta naturaleza.

# 7. Plan de correcciones prioritario

Esta sería mi hoja de ruta para llevar el proyecto a un nivel considerablemente más profesional.

## Fase 1 — Correcciones críticas

Prioridad máxima

Progreso de la fase

0/6

Corregir el comportamiento fail-open del auditor OSV.

Solucionar la detección de archivos .env y dotfiles.

Impedir resultados aprobados cuando un escaneo no puede completarse.

Corregir la ejecución de comandos mediante shell=True.

Validar destinos y redirecciones en el auditor de endpoints.

Implementar verificaciones reales de paridad SSOT, JSON y Terraform.

## Fase 2 — Fortalecimiento del motor

Prioridad alta

Incorporar análisis AST para los lenguajes principales.

Agregar detección especializada de secretos.

Mejorar la cobertura de dependencias y formatos de lockfiles.

Validar valores y directivas de cabeceras HTTP.

Fortalecer el monitor de integridad y proteger sus secretos.

Implementar pruebas de regresión para todos los escenarios de error.

## Fase 3 — Preparación profesional

Mejora estructural

Fijar imágenes Docker por digest.

Revisar todos los secretos y puertos de Compose.

Fijar las acciones externas de CI/CD por SHA.

Añadir análisis de imágenes y SBOM.

Añadir autorización explícita para operaciones destructivas y auditorías externas.

Actualizar la documentación para distinguir controles implementados de recomendaciones.

# 8. Veredicto final

# No aprobado todavía para certificación de seguridad en producción

Tu proyecto tiene una arquitectura prometedora, pero sus mecanismos actuales de validación todavía no son suficientemente fiables para considerarlos una garantía de seguridad.\
Lo más importante es corregir los falsos resultados positivos.

Mi valoración cualitativa por áreas:

| Área                          | Evaluación                    |
| ----------------------------- | ----------------------------- |
| Arquitectura y organización   | Buena                         |
| Diseño de la skill            | Buena                         |
| Seguridad de los scripts      | Necesita mejoras              |
| Detección de vulnerabilidades | Insuficiente para uso crítico |
| Cadena de suministro          | Mejorable                     |
| Protección de infraestructura | Parcial                       |
| Automatización DevSecOps      | Buena base                    |
| Preparación para producción   | No aprobada                   |

### Mi recomendación

No reconstruiría tu proyecto desde cero.

Conservaría su arquitectura, el SSOT, los scripts independientes, la integración SARIF y las plantillas. Pero transformaría el motor de auditoría en un sistema de múltiples capas, con validación real, gestión estricta de errores y pruebas automatizadas.

También cambiaría una filosofía importante: el sistema nunca debe declarar que un proyecto es seguro simplemente porque no encontró vulnerabilidades. Debe demostrar que completó satisfactoriamente todas las comprobaciones que afirma haber realizado.

Ese cambio es fundamental para que Military Cyberdefense Skill pase de ser una colección prometedora de herramientas defensivas a una herramienta de auditoría verdaderamente confiable.