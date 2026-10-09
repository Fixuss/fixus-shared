# fixus-shared

Código compartido entre las apps de Fixus, para no tener la misma lógica copiada en varios repos.

## Paquetes

### `fixus-afip` (raíz de este repo)

Consulta al padrón AFIP (`ws_sr_padron_a13`) con autenticación WSAA. Usado por `evaluador-fixus`, `tablero-fixus` y `simulador-fixus` desde sus respectivos `pages/api/buscar-cuit.js`.

Antes de la Etapa 0 del plan de unificación, este código vivía copiado 3 veces (con pequeñas diferencias entre copias). Ahora vive acá, versionado con tags de git, y cada app lo instala como dependencia:

```json
"dependencies": {
  "fixus-afip": "github:Fixuss/fixus-shared#v1.0.0"
}
```

Export principal:

```js
import { consultarCuit, AfipError } from 'fixus-afip'

const data = await consultarCuit(cuit, { certPem, keyPem })
// -> { razonSocial, actividad, estadoClave, tipoPersona, mesCierre, fechaInscripcion, domicilio }
```

Ver comentario al inicio de `index.js` para el patrón completo de uso en una API route de Next.js.

### Variables de entorno que necesita (en cada app consumidora)

- `AFIP_CERT` — certificado PEM (con `\n` escapados)
- `AFIP_KEY` — clave privada PEM (con `\n` escapados)

### `fixus-auth` (mismo paquete, `auth.js`) — agregado en la Etapa 3

Login único con rol: hashing de contraseñas y token de sesión firmado, para que el Portal le pase una sesión válida a cualquier otra app sin compartir contraseñas ni backend de sesión central. Mismo import que AFIP, mismo paquete:

```js
import { hashPassword, verifyPassword, signSession, verifySession } from 'fixus-afip'
```

Ver el comentario al inicio de `auth.js` para el patrón completo (quién firma, quién verifica, formato del token).

#### Variable de entorno que necesita

- `AUTH_SECRET` — secreto compartido para firmar/verificar la sesión. Tiene que ser **el mismo valor** en todas las apps que verifican sesión (hoy: fixus-cobros, que firma al loguear, y cada app que la Tablero/Evaluador/Simulador/Cobros valida al recibir `?sesion=`). El Portal no necesita conocerlo — solo reenvía el token que le devuelve fixus-cobros.

## Cómo versionar un cambio

1. Hacé el cambio en `index.js` (o en `auth.js`).
2. Subí un tag nuevo (ej. `v1.1.0`) siguiendo semver — si no se puede (ver nota de la Etapa 0 sobre permisos de tag de esta sesión), apuntar al commit SHA directamente funciona igual.
3. Actualizá el `package.json` de cada app consumidora para apuntar al tag/commit nuevo, y corré `npm install`.

No hace falta publicar a npm — las apps lo instalan directo desde GitHub.
