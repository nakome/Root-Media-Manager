<?php

declare (strict_types = 1);

/**
 * Voy a crear una archivo en Php para poder editar archivos y poder subir imagenes ademas de poder verlas y borrarlas.
 * El proposito de este archivo solo es con fines educacionales.
 */

define('ROOT', str_replace(DIRECTORY_SEPARATOR, '/', getcwd()));
define('DEBUG', true);
define('ROOT_MINIMUM_PHP', '7.4.0');

// Dar formato a la fecha
setlocale(LC_ALL, "es_ES", 'Spanish_Spain', 'Spanish');

// Cabeceras de seguridad
header("X-Powered-By: Moncho Varela :)");
header('Strict-Transport-Security: max-age=31536000');
header("Content-Security-Policy: img-src  'self' data:; script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'");
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer-when-downgrade');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

if (version_compare($ver = PHP_VERSION, $req = ROOT_MINIMUM_PHP, '<')) {
    $out = sprintf('Usted esta usando PHP %s, pero AntCMs necesita <strong>PHP %s</strong> para funcionar.', $ver, $req);
    exit($out);
}

// Si DEBUG es true enseñamos los errores
if (DEBUG == true) {
    @ini_set('error_reporting', (string)E_ALL);
    @ini_set('display_errors', (string) 1);
} else {
    @ini_set('error_reporting', (string)E_ALL);
    @ini_set('display_errors', (string) 0);
}

/**
 * Clase PasswordHasher para el manejo de contraseñas seguras
 *
 * <code>
 *
 *  $hasher = new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 12]);
 *  $test = $hasher->hash('demo');
 *  $hasher->verify('demo', $test)
 *
 * </code>
 */
class PasswordHasher
{

    /**
     * @var string Algoritmo de hash a utilizar
     */
    private $__hashAlgorithm;

    /**
     * @var array Opciones del algoritmo de hash
     */
    private $__options;

    /**
     * Constructor de la clase PasswordHasher
     *
     * @param string $hashAlgorithm Algoritmo de hash a utilizar
     * @param array $options Opciones del algoritmo de hash
     */
    public function __construct(string $hashAlgorithm = PASSWORD_DEFAULT, array $options = [])
    {
        $this->__hashAlgorithm = $hashAlgorithm;
        $this->__options = $options;
    }

    /**
     * Hash a la contraseña
     *
     * @param string $password Contraseña a hashear
     * @return string Hash resultante
     */
    public function hash(string $password): string
    {
        return password_hash($password, $this->__hashAlgorithm, $this->__options);
    }

    /**
     * Verificación de la contraseña
     *
     * @param string $password Contraseña sin hashear
     * @param string $hash Hash de la contraseña almacenada en la base de datos
     * @return bool Resultado de la verificación
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Comprueba si el hash necesita ser actualizado
     *
     * @param string $hash Hash de la contraseña almacenada en la base de datos
     * @return bool Resultado de la comprobación
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->__hashAlgorithm, $this->__options);
    }
}

/**
 * Trait Session
 *
 * Este trait provee métodos para manejar la sesión en PHP.
 *
 * Los métodos incluidos permiten iniciar, destruir, verificar y modificar variables de sesión.
 * También incluye un método para verificar si una clave específica existe en la sesión.
 */
trait Session
{
    /**
     * Iniciar sesión.
     *
     * Este método verifica si la sesión ya ha sido iniciada y la inicia si aún no lo ha sido.
     *
     * @return bool - Devuelve true si la sesión ya estaba iniciada o si se inició correctamente, o false si no se pudo iniciar la sesión.
     */
    public function sessionStart(): bool
    {
        // Si la sesión ya se inició, devolver true; de lo contrario, iniciar la sesión y devolver el resultado
        return session_id() || @session_start();
    }

    /**
     * Elimina uno o varios valores de la sesión.
     *
     * @param mixed ...$args  Uno o varios valores de la sesión a eliminar.
     *                        Pueden ser especificados como argumentos separados o como un arreglo.
     *                        Cada valor debe ser una clave válida de la sesión.
     * @return void
     */
    public function sessionDelete(...$args): void
    {
        // Si el primer argumento es un array, recorrerlo y eliminar cada clave
        if (is_array($args[0])) {
            foreach ($args[0] as $key) {
                unset($_SESSION[$key]);
            }
        } else {
            // Si el primer argumento no es un array, eliminar cada argumento individual
            foreach ($args as $key) {
                unset($_SESSION[$key]);
            }
        }
    }

    /**
     * Destruye la sesión actual y elimina todas las variables de sesión.
     *
     * @return void
     */
    public function sessionDestroy(): void
    {
        // Iniciar la sesión si no se ha iniciado ya
        if (!session_id()) {
            session_start();
        }

        // Eliminar todas las variables de sesión
        $_SESSION = [];

        // Destruir la sesión
        session_destroy();

        // Asegurarse de que la sesión se haya destruido correctamente
        if (session_id()) {
            // Forzar la eliminación de la sesión
            session_write_close();
        }
    }

    /**
     * Verifica si existen todas las claves proporcionadas en la sesión.
     *
     * @param string ...$keys Una lista de claves a verificar en la sesión.
     * @return bool True si todas las claves existen en la sesión, False en caso contrario.
     */
    public function sessionExists(string...$keys): bool
    {
        // Iniciar la sesión si es necesario
        if (session_status() !== PHP_SESSION_ACTIVE) {
            self::sessionStart();
        }

        // Verificar si todas las claves existen en la sesión
        $allKeysExist = array_reduce($keys, function ($exists, $key) {
            return $exists && isset($_SESSION[$key]);
        }, true);

        return $allKeysExist;
    }

    /**
     * Establecer sesión.
     *
     * @param  string $key   clave
     * @param  mixed  $value valor
     */
    public function sessionSet(string $key, $value): void
    {
        // Iniciar sesión si es necesario
        if (!session_id()) {
            self::sessionStart();
        }

        // Verificar que la clave no sea una cadena vacía
        if ($key !== '') {
            // Establecer la clave y valor en la sesión
            $_SESSION[$key] = $value;
        }
    }

    /**
     * Obtener sesión.
     *
     * @param string $key la clave de la sesión a obtener
     * @return mixed el valor de la clave de la sesión o null si la clave no existe
     */
    public function sessionGet($key)
    {
        // Iniciar sesión si es necesario
        self::sessionStart();
        // Obtener la clave
        return $_SESSION[$key] ?? null;
    }
}

/**
 * Token Trait
 * Este trait proporciona una funcionalidad para generar y verificar tokens aleatorios, y generar códigos de captcha.
 *
 * Los tokens se utilizan para la autenticación y la protección contra ataques CSRF, mientras que los códigos de captcha se utilizan para la verificación de formularios.
 * @package MediaManager
 * @category MediaManager
 */
trait Token
{

    /**
     * Generar Token
     *
     * Este método genera un token aleatorio seguro para su uso en varias aplicaciones, como la autenticación y la verificación de formularios.
     * El token se devuelve para su posterior uso.
     *
     * @param int $length (opcional) La longitud del token generado (por defecto 32)
     * @return string $token - El token generado
     */
    public function tokenGenerate($length = 32)
    {
        // Verificar si la sesión ha sido iniciada
        if ($this->sessionStart()) {
            // Generar un identificador único seguro
            $uniqId = random_bytes(16);
            // Aplicar la función hash SHA-256 al identificador único
            $sha256 = hash('sha256', $uniqId);
            // Convertir el resultado de la función hash a base 36
            $baseConvert = base_convert($sha256, 16, 36);
            // Tomar los primeros caracteres del resultado de la conversión
            $token = substr($baseConvert, 0, $length);
            // Guardar el token en la sesión
            $_SESSION['token'] = $token;
            // Devolver el token generado
            return $token;
        }
    }

    /**
     * Check token
     *
     * Este método verifica si un token enviado en una solicitud coincide con el que se guardó previamente en la sesión del usuario.
     * Se utiliza para prevenir ataques CSRF (Cross-site request forgery) y proteger la integridad de los datos del usuario.
     *
     * @param string $token - El token enviado en la solicitud
     * @return bool - Devuelve verdadero si el token coincide con el de la sesión, falso en caso contrario
     */
    public function tokenCheck(string $token = ""): bool
    {
        // Comprobar si el token es nulo
        if ($token === null) {
            return false;
        }

        // Comparar el token enviado con el de la sesión del usuario
        return $token === $this->sessionGet('token');
    }

    /**
     * Generar un código de captcha aleatorio.
     *
     * @param int $length la longitud del código, por defecto es 6
     * @param string $characters los caracteres permitidos para el código, por defecto son las letras mayúsculas del alfabeto inglés y los números del 0 al 9
     * @return string el código de captcha generado
     */
    public function tokenCaptcha(int $length = 6, string $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'): string
    {
        $randomString = '';
        $maxIndex = strlen($characters) - 1;
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $maxIndex)];
        }
        return $randomString;
    }
}

/**
 * Auth Trait
 *
 * El trait Auth contiene varias funciones que se encargan de la autenticación de usuarios en una aplicación web. Los comentarios
 * relacionados con el trait son los siguientes:
 *
 * toManyAttempts: Esta función devuelve una página HTML indicando que se han realizado demasiados intentos de acceso y
 * se ha bloqueado temporalmente el acceso. Esta página se mostrará al usuario en caso de que haya superado el número máximo
 * de intentos fallidos de inicio de sesión.
 * isLogin: Esta función verifica si el usuario ha iniciado sesión o no. Devuelve true si se han cumplido las condiciones
 * necesarias para considerar que el usuario ha iniciado sesión, y false en caso contrario.
 * login: Esta función se encarga de realizar el proceso de inicio de sesión del usuario. En primer lugar, comprueba que
 * la contraseña no esté vacía. Si hay 3 o más intentos fallidos de inicio de sesión, se bloquea el acceso del usuario temporalmente.
 * Si existe una cookie de bloqueo de usuario, se muestra una página HTML indicando que el acceso está bloqueado.
 * Si la contraseña es correcta, se insertan las variables de sesión correspondientes y se redirige al usuario a la página principal.
 * Si la contraseña es incorrecta, se incrementa el contador de intentos fallidos y se muestra un mensaje de error al usuario,
 * indicando cuántos intentos le quedan antes de ser bloqueado.
 * logout: Esta función se encarga de cerrar la sesión del usuario, eliminando todas las variables de sesión y redirigiéndolo al
 * sitio principal.
 * @package MediaManager
 * @category Trait
 */
trait Auth
{

    /**
     * toManyAttempts
     *
     * @return string   Devuelve una cadena de texto con el código HTML de una página
     *                  que indica que se han realizado demasiados intentos de acceso
     *                  y se ha bloqueado temporalmente el acceso.
     */
    public function toManyAttempts(): string
    {
        // Código HTML de la página
        return '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Acceso bloqueado</title><style>*{box-sizing:border-box}body,html{position:relative;height:100%}body{margin:0;padding:0;background:#eee}main{display:flex;justify-content:center;align-items:center;height:100%}section{margin:5px;max-width:30rem;padding:10px 20px;width:100%;border-radius:4px;background:#fff;border:1px solid #ddd}section h1{font-size:28px;line-height:1.5;margin:0;margin-bottom:10px;color:#333}section p{margin:0;margin-bottom:10px;font-size:16px;line-height:1.5;color:#777}</style></head><body><main><section><h1>Ups, demasiados intentos de acceso</h1><p>Tiene que esperar <span id="num">5</span> segundos para volver a intentarlo. </p></section><script rel="javascript">let id=document.getElementById("num"),count=5,i=setInterval(()=>{count-=1,id.textContent=count,0===count&&location.reload(!0)},1e3);</script></main></body></html>';
    }

    /**
     * Verifica si el usuario ha iniciado sesión.
     *
     * @return bool
     */
    public function isLogin(): bool
    {
        // Verificar si existen las claves necesarias en la sesión y si el hash de inicio de sesión coincide
        if ($this->sessionGet('_ip') && $this->sessionGet('_time') && $this->login_hash == $this->sessionGet('_login_hash')) {
            return true;
        }
        return false;
    }

    /**
     * login
     *
     * @return void
     */
    public function login(): void
    {
        // Verificar que no esté vacía la contraseña
        if (empty($this->getOption('password'))) {
            $this->error('La configuración de la contraseña no puede estar vacía');
        }

        // Iniciamos la clase PasswordHasher
        $hasher = new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 50]);

        // Obtener el número de intentos de acceso fallidos
        $intentos = $this->sessionGet('intentos_acceso');

        // Si hay 3 o más intentos, bloquear el acceso
        if ($intentos >= 3) {
            // Insertar una cookie de bloqueo de usuario durante 5 segundos
            setcookie('usuario_bloqueado', (string)true, time() + 5, "/", "", true, true);
            // Reiniciar el contador de intentos de acceso
            $this->sessionSet('intentos_acceso', 0);
            // Redirigir al usuario a la página principal
            $this->redirect($this->getOption('Site_url'));
        }

        // Comprobar si existe la cookie de bloqueo de usuario
        if (array_key_exists('usuario_bloqueado', $_COOKIE)) {
            // Mostrar la plantilla de error de demasiados intentos
            die($this->toManyAttempts());
            // Salir del script
            exit();
        } else {

            $password = trim($this->getPost('password', true));
            // Comprobar si la contraseña es correcta
            if ($hasher->verify($password, $this->getOption('password'))) {
                // Insertar las variables de sesión correspondientes
                $this->sessionSet('_login_hash', $this->login_hash); // Insertar el hash de inicio de sesión
                $this->sessionSet('_ip', $this->ip); // Guardar la dirección IP del usuario
                $this->sessionSet('_time', date('m-d-Y h:m:s')); // Guardar la fecha y hora de inicio de sesión
                $this->sessionSet('intentos_acceso', 0); // Reiniciar el contador de intentos de acceso
                // Redirigir al usuario a la página principal
                $this->redirect($this->getOption('Site_url'));
            } else {
                // Incrementar el contador de intentos de acceso fallidos
                $count = $intentos + 1;
                // Insertar el nuevo valor del contador en la sesión
                $this->sessionSet('intentos_acceso', $count);
                // Mostrar un mensaje de error y redirigir al usuario a la página principal
                $this->msgSet('Error 🤨', "La contraseña es incorrecta te quedan " . (abs($count - 3)) . " intentos.");
                $this->redirect($this->getOption('Site_url'));
            }
        }
    }

    /**
     * logout
     * Esta función se encarga de cerrar sesión del usuario, eliminando todas las variables de sesión y redirigiendo al sitio principal.
     *
     * @return void
     */
    public function logout(): void
    {
        // Verificamos si la sesión está iniciada
        if ($this->sessionStart()) {
            // Eliminamos las variables de sesión correspondientes
            $this->sessionDelete('_login_hash');
            $this->sessionDelete('_uid');
            $this->sessionDelete('_ip');
            $this->sessionDelete('_time');
            $this->sessionDestroy();
            // Redirigimos al sitio principal
            $this->redirect($this->getOption('Site_url'));
        }
    }
}

/**
 * Trait Msg
 * Este trait proporciona métodos para mostrar mensajes en una página web utilizando la sesión del usuario.
 * Los mensajes pueden ser establecidos utilizando el método msgSet() y posteriormente recuperados y mostrados
 * en la página web utilizando el método msgGet().
 * @package MediaManager
 * @category Trait
 */
trait Msg
{

    /**
     * Función para obtener un mensaje.
     *
     * @param string $callback El callback para obtener el mensaje
     *
     * @return callback
     */
    public function msgGet()
    {
        // Verificamos si hay un mensaje almacenado en la sesión
        if ($this->sessionGet('msg')) {
            $msg = $this->sessionGet('msg'); // Obtenemos el mensaje
            $this->sessionDelete('msg'); // Borramos el mensaje de la sesión
        }
        // Si existe un mensaje almacenado, lo mostramos en una ventana emergente
        if (isset($msg)) {
            return '<script type="text/javascript">message("' . $msg['title'] . '","' . $msg['msg'] . '");</script>';
        }
    }

    /**
     * Establece un mensaje para ser mostrado en la página.
     *
     * @param string $title El título del mensaje.
     * @param string $msg   El contenido del mensaje.
     */
    public function msgSet($title, $msg)
    {
        // Creamos un array con los datos del mensaje
        $data = array(
            'title' => $title,
            'msg' => $msg,
        );
        // Almacenamos el mensaje en la sesión para que sea visible en la próxima página
        $this->sessionSet('msg', $data);
    }
}

/**
 * Trait Icons
 * Este trait proporciona métodos para mostrar los iconos de en una página web.
 * checkExtension: Comprueba si una extensión está en el valor de alguno de los tipos de extensión y devuelve la clave y el valor correspondiente
 * icon:Función para obtener el icono correspondiente según el nombre y la extensión de un archivo.
 * renderIconByType: Función para redenderizar un icono especifico a partir de los argumentos obtenidos.
 * @package MediaManager
 * @category Trait
 */
trait Icons
{
    /**
     * Comprueba si una extensión está en el valor de alguno de los tipos de extensión y devuelve la clave y el valor correspondiente
     *
     * @param string $extension La extensión que se va a comprobar
     * @return array Devuelve un array con la información sobre la extensión
     */
    public function checkExtension(string $extension): array
    {
        // Lista de extensiones permitidas
        $extensionsType = [
            'isImage' => $this->getOption('imageSupport'),
            'isVideo' => $this->getOption('videoSupport'),
            'isAudio' => $this->getOption('audioSupport'),
            'isEditable' => $this->getOption('editableFilesSupport'),
            'nonEditable' => $this->getOption('nonEditableFilesSupport'),
        ];
        // Inicializa un array vacío para guardar los valores correspondientes
        $result = [];
        // Recorre el array de tipos de extensión
        foreach ($extensionsType as $key => $value) {
            // Si la extensión está en el valor de algún tipo de extensión
            if (in_array($extension, $value)) {
                // Agrega la clave y el valor correspondiente al array de resultados
                $result[$key] = $value;
            }
        }
        // Devuelve la información sobre la extensión
        return [
            'isValid' => true,
            'extType' => $result ? array_keys($result)[0] : null,
        ];
    }

    /**
     * Función para obtener el icono correspondiente según el nombre y la extensión de un archivo.
     *
     * @param string $name Nombre del archivo
     * @return void
     */
    public function icon(string $name = "")
    {
        // Definición de los diferentes iconos
        $icons = [
            'home' => '<path d="M8.707 1.5a1 1 0 0 0-1.414 0L.646 8.146a.5.5 0 0 0 .708.708L2 8.207V13.5A1.5 1.5 0 0 0 3.5 15h9a1.5 1.5 0 0 0 1.5-1.5V8.207l.646.647a.5.5 0 0 0 .708-.708L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.707 1.5ZM13 7.207V13.5a.5.5 0 0 1-.5.5h-9a.5.5 0 0 1-.5-.5V7.207l5-5 5 5Z"/>',
            'xml' => '<path d="M14 4.5V14a2 2 0 0 1-2 2v-1a1 1 0 0 0 1-1V4.5h-2A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v9H2V2a2 2 0 0 1 2-2h5.5L14 4.5ZM3.527 11.85h-.893l-.823 1.439h-.036L.943 11.85H.012l1.227 1.983L0 15.85h.861l.853-1.415h.035l.85 1.415h.908l-1.254-1.992 1.274-2.007Zm.954 3.999v-2.66h.038l.952 2.159h.516l.946-2.16h.038v2.661h.715V11.85h-.8l-1.14 2.596h-.025L4.58 11.85h-.806v3.999h.706Zm4.71-.674h1.696v.674H8.4V11.85h.791v3.325Z"/>',
            'folder' => '<path d="M.54 3.87.5 3a2 2 0 0 1 2-2h3.672a2 2 0 0 1 1.414.586l.828.828A2 2 0 0 0 9.828 3h3.982a2 2 0 0 1 1.992 2.181l-.637 7A2 2 0 0 1 13.174 14H2.826a2 2 0 0 1-1.991-1.819l-.637-7a1.99 1.99 0 0 1 .342-1.31zM2.19 4a1 1 0 0 0-.996 1.09l.637 7a1 1 0 0 0 .995.91h10.348a1 1 0 0 0 .995-.91l.637-7A1 1 0 0 0 13.81 4H2.19zm4.69-1.707A1 1 0 0 0 6.172 2H2.5a1 1 0 0 0-1 .981l.006.139C1.72 3.042 1.95 3 2.19 3h5.396l-.707-.707z"/>',
            'image' => '<path d="M6.002 5.5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/><path d="M1.5 2A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2h-13zm13 1a.5.5 0 0 1 .5.5v6l-3.775-1.947a.5.5 0 0 0-.577.093l-3.71 3.71-2.66-1.772a.5.5 0 0 0-.63.062L1.002 12v.54A.505.505 0 0 1 1 12.5v-9a.5.5 0 0 1 .5-.5h13z"/>',
            'pdf' => 'path d="M5.523 12.424c.14-.082.293-.162.459-.238a7.878 7.878 0 0 1-.45.606c-.28.337-.498.516-.635.572a.266.266 0 0 1-.035.012.282.282 0 0 1-.026-.044c-.056-.11-.054-.216.04-.36.106-.165.319-.354.647-.548zm2.455-1.647c-.119.025-.237.05-.356.078a21.148 21.148 0 0 0 .5-1.05 12.045 12.045 0 0 0 .51.858c-.217.032-.436.07-.654.114zm2.525.939a3.881 3.881 0 0 1-.435-.41c.228.005.434.022.612.054.317.057.466.147.518.209a.095.095 0 0 1 .026.064.436.436 0 0 1-.06.2.307.307 0 0 1-.094.124.107.107 0 0 1-.069.015c-.09-.003-.258-.066-.498-.256zM8.278 6.97c-.04.244-.108.524-.2.829a4.86 4.86 0 0 1-.089-.346c-.076-.353-.087-.63-.046-.822.038-.177.11-.248.196-.283a.517.517 0 0 1 .145-.04c.013.03.028.092.032.198.005.122-.007.277-.038.465z"/><path fill-rule="evenodd" d="M4 0h5.293A1 1 0 0 1 10 .293L13.707 4a1 1 0 0 1 .293.707V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2zm5.5 1.5v2a1 1 0 0 0 1 1h2l-3-3zM4.165 13.668c.09.18.23.343.438.419.207.075.412.04.58-.03.318-.13.635-.436.926-.786.333-.401.683-.927 1.021-1.51a11.651 11.651 0 0 1 1.997-.406c.3.383.61.713.91.95.28.22.603.403.934.417a.856.856 0 0 0 .51-.138c.155-.101.27-.247.354-.416.09-.181.145-.37.138-.563a.844.844 0 0 0-.2-.518c-.226-.27-.596-.4-.96-.465a5.76 5.76 0 0 0-1.335-.05 10.954 10.954 0 0 1-.98-1.686c.25-.66.437-1.284.52-1.794.036-.218.055-.426.048-.614a1.238 1.238 0 0 0-.127-.538.7.7 0 0 0-.477-.365c-.202-.043-.41 0-.601.077-.377.15-.576.47-.651.823-.073.34-.04.736.046 1.136.088.406.238.848.43 1.295a19.697 19.697 0 0 1-1.062 2.227 7.662 7.662 0 0 0-1.482.645c-.37.22-.699.48-.897.787-.21.326-.275.714-.08 1.103z"/>',
            'md' => '<path d="M14 3a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h12zM2 2a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H2z"/><path fill-rule="evenodd" d="M9.146 8.146a.5.5 0 0 1 .708 0L11.5 9.793l1.646-1.647a.5.5 0 0 1 .708.708l-2 2a.5.5 0 0 1-.708 0l-2-2a.5.5 0 0 1 0-.708z"/><path fill-rule="evenodd" d="M11.5 5a.5.5 0 0 1 .5.5v4a.5.5 0 0 1-1 0v-4a.5.5 0 0 1 .5-.5z"/><path d="M3.56 11V7.01h.056l1.428 3.239h.774l1.42-3.24h.056V11h1.073V5.001h-1.2l-1.71 3.894h-.039l-1.71-3.894H2.5V11h1.06z"/>',
            'js' => '<path fill-rule="evenodd" d="M14 4.5V14a2 2 0 0 1-2 2H8v-1h4a1 1 0 0 0 1-1V4.5h-2A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v9H2V2a2 2 0 0 1 2-2h5.5L14 4.5ZM3.186 15.29a1.176 1.176 0 0 1-.111-.449h.765a.578.578 0 0 0 .255.384c.07.049.153.087.249.114.095.028.202.041.319.041.164 0 .302-.023.413-.07a.559.559 0 0 0 .255-.193.507.507 0 0 0 .085-.29.387.387 0 0 0-.153-.326c-.101-.08-.255-.144-.462-.193l-.619-.143a1.72 1.72 0 0 1-.539-.214 1.001 1.001 0 0 1-.351-.367 1.068 1.068 0 0 1-.123-.524c0-.244.063-.457.19-.639.127-.181.303-.322.528-.422.224-.1.483-.149.776-.149.305 0 .564.05.78.152.216.102.383.239.5.41.12.17.186.359.2.566h-.75a.56.56 0 0 0-.12-.258.624.624 0 0 0-.247-.181.923.923 0 0 0-.369-.068c-.217 0-.388.05-.513.152a.472.472 0 0 0-.184.384c0 .121.048.22.143.3a.97.97 0 0 0 .405.175l.62.143c.218.05.406.12.566.211.16.09.285.21.375.358.09.148.135.335.135.56 0 .247-.063.466-.188.656a1.216 1.216 0 0 1-.539.439c-.234.105-.52.158-.858.158-.254 0-.476-.03-.665-.09a1.404 1.404 0 0 1-.478-.252 1.13 1.13 0 0 1-.29-.375Zm-3.104-.033A1.32 1.32 0 0 1 0 14.791h.765a.576.576 0 0 0 .073.27.499.499 0 0 0 .454.246c.19 0 .33-.055.422-.164.092-.11.138-.265.138-.466v-2.745h.79v2.725c0 .44-.119.774-.357 1.005-.236.23-.564.345-.984.345a1.59 1.59 0 0 1-.569-.094 1.145 1.145 0 0 1-.407-.266 1.14 1.14 0 0 1-.243-.39Z"/>',
            'css' => '<path fill-rule="evenodd" d="M14 4.5V14a2 2 0 0 1-2 2h-1v-1h1a1 1 0 0 0 1-1V4.5h-2A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v9H2V2a2 2 0 0 1 2-2h5.5L14 4.5ZM3.397 14.841a1.13 1.13 0 0 0 .401.823c.13.108.289.192.478.252.19.061.411.091.665.091.338 0 .624-.053.859-.158.236-.105.416-.252.539-.44.125-.189.187-.408.187-.656 0-.224-.045-.41-.134-.56a1.001 1.001 0 0 0-.375-.357 2.027 2.027 0 0 0-.566-.21l-.621-.144a.97.97 0 0 1-.404-.176.37.37 0 0 1-.144-.299c0-.156.062-.284.185-.384.125-.101.296-.152.512-.152.143 0 .266.023.37.068a.624.624 0 0 1 .246.181.56.56 0 0 1 .12.258h.75a1.092 1.092 0 0 0-.2-.566 1.21 1.21 0 0 0-.5-.41 1.813 1.813 0 0 0-.78-.152c-.293 0-.551.05-.776.15-.225.099-.4.24-.527.421-.127.182-.19.395-.19.639 0 .201.04.376.122.524.082.149.2.27.352.367.152.095.332.167.539.213l.618.144c.207.049.361.113.463.193a.387.387 0 0 1 .152.326.505.505 0 0 1-.085.29.559.559 0 0 1-.255.193c-.111.047-.249.07-.413.07-.117 0-.223-.013-.32-.04a.838.838 0 0 1-.248-.115.578.578 0 0 1-.255-.384h-.765ZM.806 13.693c0-.248.034-.46.102-.633a.868.868 0 0 1 .302-.399.814.814 0 0 1 .475-.137c.15 0 .283.032.398.097a.7.7 0 0 1 .272.26.85.85 0 0 1 .12.381h.765v-.072a1.33 1.33 0 0 0-.466-.964 1.441 1.441 0 0 0-.489-.272 1.838 1.838 0 0 0-.606-.097c-.356 0-.66.074-.911.223-.25.148-.44.359-.572.632-.13.274-.196.6-.196.979v.498c0 .379.064.704.193.976.131.271.322.48.572.626.25.145.554.217.914.217.293 0 .554-.055.785-.164.23-.11.414-.26.55-.454a1.27 1.27 0 0 0 .226-.674v-.076h-.764a.799.799 0 0 1-.118.363.7.7 0 0 1-.272.25.874.874 0 0 1-.401.087.845.845 0 0 1-.478-.132.833.833 0 0 1-.299-.392 1.699 1.699 0 0 1-.102-.627v-.495ZM6.78 15.29a1.176 1.176 0 0 1-.111-.449h.764a.578.578 0 0 0 .255.384c.07.049.154.087.25.114.095.028.201.041.319.041.164 0 .301-.023.413-.07a.559.559 0 0 0 .255-.193.507.507 0 0 0 .085-.29.387.387 0 0 0-.153-.326c-.101-.08-.256-.144-.463-.193l-.618-.143a1.72 1.72 0 0 1-.539-.214 1 1 0 0 1-.351-.367 1.068 1.068 0 0 1-.123-.524c0-.244.063-.457.19-.639.127-.181.303-.322.527-.422.225-.1.484-.149.777-.149.304 0 .564.05.779.152.217.102.384.239.5.41.12.17.187.359.2.566h-.75a.56.56 0 0 0-.12-.258.624.624 0 0 0-.246-.181.923.923 0 0 0-.37-.068c-.216 0-.387.05-.512.152a.472.472 0 0 0-.184.384c0 .121.047.22.143.3a.97.97 0 0 0 .404.175l.621.143c.217.05.406.12.566.211.16.09.285.21.375.358.09.148.135.335.135.56 0 .247-.063.466-.188.656a1.216 1.216 0 0 1-.539.439c-.234.105-.52.158-.858.158-.254 0-.476-.03-.665-.09a1.404 1.404 0 0 1-.478-.252 1.13 1.13 0 0 1-.29-.375Z"/>',
            'html' => '<path fill-rule="evenodd" d="M14 4.5V11h-1V4.5h-2A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v9H2V2a2 2 0 0 1 2-2h5.5L14 4.5Zm-9.736 7.35v3.999h-.791v-1.714H1.79v1.714H1V11.85h.791v1.626h1.682V11.85h.79Zm2.251.662v3.337h-.794v-3.337H4.588v-.662h3.064v.662H6.515Zm2.176 3.337v-2.66h.038l.952 2.159h.516l.946-2.16h.038v2.661h.715V11.85h-.8l-1.14 2.596H9.93L8.79 11.85h-.805v3.999h.706Zm4.71-.674h1.696v.674H12.61V11.85h.79v3.325Z"/>',
            'video' => '<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M6.271 5.055a.5.5 0 0 1 .52.038l3.5 2.5a.5.5 0 0 1 0 .814l-3.5 2.5A.5.5 0 0 1 6 10.5v-5a.5.5 0 0 1 .271-.445z"/>',
            'code' => '<path d="M14 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h12zM2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H2z"/><path d="M6.854 4.646a.5.5 0 0 1 0 .708L4.207 8l2.647 2.646a.5.5 0 0 1-.708.708l-3-3a.5.5 0 0 1 0-.708l3-3a.5.5 0 0 1 .708 0zm2.292 0a.5.5 0 0 0 0 .708L11.793 8l-2.647 2.646a.5.5 0 0 0 .708.708l3-3a.5.5 0 0 0 0-.708l-3-3a.5.5 0 0 0-.708 0z"/>',
            'info' => '<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="m8.93 6.588-2.29.287-.082.38.45.083c.294.07.352.176.288.469l-.738 3.468c-.194.897.105 1.319.808 1.319.545 0 1.178-.252 1.465-.598l.088-.416c-.2.176-.492.246-.686.246-.275 0-.375-.193-.304-.533L8.93 6.588zM9 4.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0z"/>',
            'json' => '<path fill-rule="evenodd" d="M14 4.5V11h-1V4.5h-2A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v9H2V2a2 2 0 0 1 2-2h5.5L14 4.5ZM4.151 15.29a1.176 1.176 0 0 1-.111-.449h.764a.578.578 0 0 0 .255.384c.07.049.154.087.25.114.095.028.201.041.319.041.164 0 .301-.023.413-.07a.559.559 0 0 0 .255-.193.507.507 0 0 0 .084-.29.387.387 0 0 0-.152-.326c-.101-.08-.256-.144-.463-.193l-.618-.143a1.72 1.72 0 0 1-.539-.214 1.001 1.001 0 0 1-.352-.367 1.068 1.068 0 0 1-.123-.524c0-.244.064-.457.19-.639.128-.181.304-.322.528-.422.225-.1.484-.149.777-.149.304 0 .564.05.779.152.217.102.384.239.5.41.12.17.186.359.2.566h-.75a.56.56 0 0 0-.12-.258.624.624 0 0 0-.246-.181.923.923 0 0 0-.37-.068c-.216 0-.387.05-.512.152a.472.472 0 0 0-.185.384c0 .121.048.22.144.3a.97.97 0 0 0 .404.175l.621.143c.217.05.406.12.566.211a1 1 0 0 1 .375.358c.09.148.135.335.135.56 0 .247-.063.466-.188.656a1.216 1.216 0 0 1-.539.439c-.234.105-.52.158-.858.158-.254 0-.476-.03-.665-.09a1.404 1.404 0 0 1-.478-.252 1.13 1.13 0 0 1-.29-.375Zm-3.104-.033a1.32 1.32 0 0 1-.082-.466h.764a.576.576 0 0 0 .074.27.499.499 0 0 0 .454.246c.19 0 .33-.055.422-.164.091-.11.137-.265.137-.466v-2.745h.791v2.725c0 .44-.119.774-.357 1.005-.237.23-.565.345-.985.345a1.59 1.59 0 0 1-.568-.094 1.145 1.145 0 0 1-.407-.266 1.14 1.14 0 0 1-.243-.39Zm9.091-1.585v.522c0 .256-.039.47-.117.641a.862.862 0 0 1-.322.387.877.877 0 0 1-.47.126.883.883 0 0 1-.47-.126.87.87 0 0 1-.32-.387 1.55 1.55 0 0 1-.117-.641v-.522c0-.258.039-.471.117-.641a.87.87 0 0 1 .32-.387.868.868 0 0 1 .47-.129c.177 0 .333.043.47.129a.862.862 0 0 1 .322.387c.078.17.117.383.117.641Zm.803.519v-.513c0-.377-.069-.701-.205-.973a1.46 1.46 0 0 0-.59-.63c-.253-.146-.559-.22-.916-.22-.356 0-.662.074-.92.22a1.441 1.441 0 0 0-.589.628c-.137.271-.205.596-.205.975v.513c0 .375.068.699.205.973.137.271.333.48.589.626.258.145.564.217.92.217.357 0 .663-.072.917-.217.256-.146.452-.355.589-.626.136-.274.205-.598.205-.973Zm1.29-.935v2.675h-.746v-3.999h.662l1.752 2.66h.032v-2.66h.75v4h-.656l-1.761-2.676h-.032Z"/>',
            'php' => '<path fill-rule="evenodd" d="M14 4.5V14a2 2 0 0 1-2 2h-1v-1h1a1 1 0 0 0 1-1V4.5h-2A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v9H2V2a2 2 0 0 1 2-2h5.5L14 4.5ZM1.6 11.85H0v3.999h.791v-1.342h.803c.287 0 .531-.057.732-.173.203-.117.358-.275.463-.474a1.42 1.42 0 0 0 .161-.677c0-.25-.053-.476-.158-.677a1.176 1.176 0 0 0-.46-.477c-.2-.12-.443-.179-.732-.179Zm.545 1.333a.795.795 0 0 1-.085.38.574.574 0 0 1-.238.241.794.794 0 0 1-.375.082H.788V12.48h.66c.218 0 .389.06.512.181.123.122.185.295.185.522Zm4.48 2.666V11.85h-.79v1.626H4.153V11.85h-.79v3.999h.79v-1.714h1.682v1.714h.79Zm.703-3.999h1.6c.288 0 .533.06.732.179.2.117.354.276.46.477.105.201.158.427.158.677 0 .25-.054.476-.161.677-.106.199-.26.357-.463.474a1.452 1.452 0 0 1-.733.173H8.12v1.342h-.791V11.85Zm2.06 1.714a.795.795 0 0 0 .084-.381c0-.227-.061-.4-.184-.521-.123-.122-.294-.182-.513-.182h-.66v1.406h.66a.794.794 0 0 0 .375-.082.574.574 0 0 0 .237-.24Z"/>',
            'sql' => '<path fill-rule="evenodd" d="M14 4.5V14a2 2 0 0 1-2 2v-1a1 1 0 0 0 1-1V4.5h-2A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v9H2V2a2 2 0 0 1 2-2h5.5L14 4.5ZM0 14.841a1.129 1.129 0 0 0 .401.823c.13.108.288.192.478.252s.411.091.665.091c.338 0 .624-.053.858-.158.237-.106.416-.252.54-.44a1.17 1.17 0 0 0 .187-.656c0-.224-.045-.41-.135-.56a1 1 0 0 0-.375-.357 2.027 2.027 0 0 0-.565-.21l-.621-.144a.97.97 0 0 1-.405-.176.369.369 0 0 1-.143-.299c0-.156.061-.284.184-.384.125-.101.296-.152.513-.152.143 0 .266.022.37.068a.624.624 0 0 1 .245.181.56.56 0 0 1 .12.258h.75a1.092 1.092 0 0 0-.199-.566 1.21 1.21 0 0 0-.5-.41 1.813 1.813 0 0 0-.78-.152c-.293 0-.552.05-.776.15-.225.099-.4.24-.528.421-.127.182-.19.395-.19.639 0 .201.04.376.123.524.082.149.199.27.351.367.153.095.332.167.54.213l.618.144c.207.049.36.113.462.193a.387.387 0 0 1 .153.325c0 .11-.029.207-.085.29A.558.558 0 0 1 2 15.31c-.111.047-.249.07-.413.07-.117 0-.224-.013-.32-.04a.835.835 0 0 1-.248-.115.579.579 0 0 1-.255-.384H0Zm6.878 1.489-.507-.739c.176-.162.31-.362.401-.6.092-.239.138-.507.138-.806v-.501c0-.371-.07-.693-.208-.967a1.495 1.495 0 0 0-.589-.636c-.256-.15-.561-.225-.917-.225-.351 0-.656.075-.914.225-.256.149-.453.36-.592.636a2.138 2.138 0 0 0-.205.967v.5c0 .37.069.691.205.965.139.273.336.485.592.636a1.8 1.8 0 0 0 .914.222 1.8 1.8 0 0 0 .6-.1l.294.422h.788ZM4.262 14.2v-.522c0-.246.038-.456.114-.63a.91.91 0 0 1 .325-.398.885.885 0 0 1 .495-.138c.192 0 .357.046.495.138a.88.88 0 0 1 .325.398c.077.174.115.384.115.63v.522c0 .164-.018.312-.053.445-.035.13-.087.244-.155.34l-.106-.14-.105-.147h-.733l.451.65a.638.638 0 0 1-.251.047.872.872 0 0 1-.487-.147.916.916 0 0 1-.32-.404 1.67 1.67 0 0 1-.11-.644Zm3.986 1.057h1.696v.674H7.457v-3.999h.79v3.325Z"/>',
            'excel' => '<path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v4h10V2a1 1 0 0 0-1-1H4zm9 6h-3v2h3V7zm0 3h-3v2h3v-2zm0 3h-3v2h2a1 1 0 0 0 1-1v-1zm-4 2v-2H6v2h3zm-4 0v-2H3v1a1 1 0 0 0 1 1h1zm-2-3h2v-2H3v2zm0-3h2V7H3v2zm3-2v2h3V7H6zm3 3H6v2h3v-2z"/>',
            'word' => '<path d="M5.485 6.879a.5.5 0 1 0-.97.242l1.5 6a.5.5 0 0 0 .967.01L8 9.402l1.018 3.73a.5.5 0 0 0 .967-.01l1.5-6a.5.5 0 0 0-.97-.242l-1.036 4.144-.997-3.655a.5.5 0 0 0-.964 0l-.997 3.655L5.485 6.88z"/><path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2zM9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5v2z"/>',
            'powerpoint' => '<path d="M7 7.78V5.22c0-.096.106-.156.19-.106l2.13 1.279a.125.125 0 0 1 0 .214l-2.13 1.28A.125.125 0 0 1 7 7.778z"/><path d="M12 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2zM5 4h6a.5.5 0 0 1 .496.438l.5 4A.5.5 0 0 1 11.5 9h-3v2.016c.863.055 1.5.251 1.5.484 0 .276-.895.5-2 .5s-2-.224-2-.5c0-.233.637-.429 1.5-.484V9h-3a.5.5 0 0 1-.496-.562l.5-4A.5.5 0 0 1 5 4z"/>',
            'font' => '<path d="M10.943 6H5.057L5 8h.5c.18-1.096.356-1.192 1.694-1.235l.293-.01v5.09c0 .47-.1.582-.898.655v.5H9.41v-.5c-.803-.073-.903-.184-.903-.654V6.755l.298.01c1.338.043 1.514.14 1.694 1.235h.5l-.057-2z"/><path d="M14 4.5V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2h5.5L14 4.5zm-3 0A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4.5h-2z"/>',
            'db' => '<path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313ZM13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A4.92 4.92 0 0 0 13 5.698ZM14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13V4Zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A4.92 4.92 0 0 0 13 8.698Zm0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525Z"/>',
            'plus' => '<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M8 4a.5.5 0 0 1 .5.5v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3A.5.5 0 0 1 8 4z"/>',
            'back' => '<path d="M5.83 5.146a.5.5 0 0 0 0 .708L7.975 8l-2.147 2.146a.5.5 0 0 0 .707.708l2.147-2.147 2.146 2.147a.5.5 0 0 0 .707-.708L9.39 8l2.146-2.146a.5.5 0 0 0-.707-.708L8.683 7.293 6.536 5.146a.5.5 0 0 0-.707 0z"/><path d="M13.683 1a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2h-7.08a2 2 0 0 1-1.519-.698L.241 8.65a1 1 0 0 1 0-1.302L5.084 1.7A2 2 0 0 1 6.603 1h7.08zm-7.08 1a1 1 0 0 0-.76.35L1 8l4.844 5.65a1 1 0 0 0 .759.35h7.08a1 1 0 0 0 1-1V3a1 1 0 0 0-1-1h-7.08z"/>',
            'upload' => '<path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 1.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1-.708.708L8.5 2.707V11.5a.5.5 0 0 1-1 0V2.707L5.354 4.854a.5.5 0 1 1-.708-.708l3-3z"/>',
            'trash' => '<path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/><path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>',
            'auth' => '<path d="M8.5 10c-.276 0-.5-.448-.5-1s.224-1 .5-1 .5.448.5 1-.224 1-.5 1z"/><path d="M10.828.122A.5.5 0 0 1 11 .5V1h.5A1.5 1.5 0 0 1 13 2.5V15h1.5a.5.5 0 0 1 0 1h-13a.5.5 0 0 1 0-1H3V1.5a.5.5 0 0 1 .43-.495l7-1a.5.5 0 0 1 .398.117zM11.5 2H11v13h1V2.5a.5.5 0 0 0-.5-.5zM4 1.934V15h6V1.077l-6 .857z"/>',
            'zip' => '<path d="M6.5 7.5a1 1 0 0 1 1-1h1a1 1 0 0 1 1 1v.938l.4 1.599a1 1 0 0 1-.416 1.074l-.93.62a1 1 0 0 1-1.109 0l-.93-.62a1 1 0 0 1-.415-1.074l.4-1.599V7.5zm2 0h-1v.938a1 1 0 0 1-.03.243l-.4 1.598.93.62.93-.62-.4-1.598a1 1 0 0 1-.03-.243V7.5z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2zm5.5-1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H9v1H8v1h1v1H8v1h1v1H7.5V5h-1V4h1V3h-1V2h1V1z"/>',
            'external' => '<path fill-rule="evenodd" d="M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"/><path fill-rule="evenodd" d="M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"/>',
            'download' => '<path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>',
            'audio' => '<path d="M4 8a1 1 0 1 0 0-2 1 1 0 0 0 0 2Zm9-1a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM7 6a1 1 0 0 0 0 2h2a1 1 0 1 0 0-2H7Z"/><path d="M1.5 2A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2h-13ZM1 3.5a.5.5 0 0 1 .5-.5h13a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-.691l-1.362-2.724A.5.5 0 0 0 12 10H4a.5.5 0 0 0-.447.276L2.19 13H1.5a.5.5 0 0 1-.5-.5v-9ZM11.691 11l1 2H3.309l1-2h7.382Z"/>',
        ];
        // Imprimimos el svg
        return '<svg  viewBox="0 0 16 16" class="icon-' . $name . '">' . trim($icons[$name]) . '</svg>';
    }

    /**
     * Función para redenderizar un icono especifico a partir de los argumentos obtenidos
     *
     * @param string $extType
     * @param string $fileext
     * @param string $filetype
     * @return string
     */
    public function renderIconByType($extType = "", string $fileext = "", string $filetype = ""): string
    {
        $iconMap = [
            'isImage' => 'image',
            'isVideo' => 'video',
            'isAudio' => 'audio',
            'isEditable' => [
                'xml' => 'xml',
                'sql' => 'sql',
                'json' => 'json',
                'html' => 'html',
                'php' => 'php',
                'md' => 'md',
                'css' => 'css',
                'js' => 'js',
            ],
            'nonEditable' => [
                'pdf' => 'pdf',
                'docx' => 'word',
                'xlsx' => 'excel',
                'pptx' => 'powerpoint',
                'ttf' => 'font',
                'otf' => 'font',
                'woff' => 'font',
                'woff2' => 'font',
                'sqlite3' => 'db',
                'db' => 'db',
                'sqlite' => 'db',
                'zip' => 'zip',
            ],
        ];

        if (isset($iconMap[$extType])) {
            if (is_array($iconMap[$extType])) {
                // si $extType es 'isEditable' o 'nonEditable', buscar en el subarray
                if (isset($iconMap[$extType][$fileext])) {
                    $icon = $this->icon($iconMap[$extType][$fileext]);
                } else {
                    $icon = $this->icon('code');
                }
            } else {
                // si $extType es 'isImage' o 'isVideo', usar el valor directamente
                $icon = $this->icon($iconMap[$extType]);
            }
        } else {
            $icon = $this->icon('code');
        }

        return $icon;
    }

}

/**
 * Trait Utils
 * Este trait proporciona utilidades para la clase MediaManager.
 * unzip: Descomprime un archivo ZIP.
 * getWebServerDetails: Devuelve una cadena de texto con los detalles del servidor web, incluyendo el software y la versión de PHP.
 * removeFile: Función para borrar archivos.
 * saveContent: Función que permite guardar el contenido de un archivo.
 * moveFiles: Función que permite mover un archivo de una ubicación a otra.
 * moveDir: Función para mover una carpeta entera.
 * isRoot: Función para comprobar si una URL tiene segmentos.
 * parseUrl: La función parseUrl() toma una URL como entrada y devuelve una nueva URL sin diagonales invertidas dobles en su ruta.
 * sanitizeFileContents: Sanitiza el contenido que hay dentro de file_get_contents.
 * checkIsImage: Comprobar si es una imagen.
 * checkIsEditable: Comprueba si es un archivo editable
 * debug: Obtener información de los datos en formato JSON y devolverla como HTML con una etiqueta de detalles plegable.
 * getPost: $_POST con extras de seguridad.
 * get: $_GET con extras de seguridad.
 * formatFileSize: Convierte un tamaño de archivo en Bytes a una unidad de medida más legible para el usuario, como KB, MB, GB o TB.
 * createBreadcrumb: Genera el breadcrumb en formato HTML.
 * error: Proporciona un mensaje de error con opcion de codigo de estado.
 * redirect: Redirecciona a una URL.
 * cleanName: Elimina caracteres especiales como acentos y comas.
 * removeDir: Elimina un directorio y su contenido de forma recursiva.
 * createDir: Crea una carpeta en el directorio especificado.
 * createFile: Crea un archivo en el directorio especificado.
 * @package MediaManager
 * @category Trait
 */
trait Utils
{

    /**
     * Descomprime un archivo ZIP.
     *
     * @param string $zip_file Ruta del archivo ZIP a descomprimir.
     * @param string $destination Ruta donde se almacenarán los archivos descomprimidos.
     * @return bool True si el archivo ZIP se descomprimió correctamente, de lo contrario False.
     */
    public function unzip($zip_file, $destination)
    {
        // Verifica si el archivo ZIP existe.
        if (!file_exists($zip_file)) {
            echo "El archivo ZIP no existe.";
            return false;
        }

        // Crea un objeto ZipArchive.
        $zip = new ZipArchive();

        // Abre el archivo ZIP.
        if ($zip->open($zip_file) === true) {
            // Extrae los archivos del archivo ZIP en la ruta de destino especificada.
            $zip->extractTo($destination);
            // Cierra el archivo ZIP.
            $zip->close();
            $this->msgSet('Bien 😁', "El archivo {$filename} se descomprimió correctamente.");
            $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode(dirname($destination)));
            return true;
        } else {
            $this->msgSet('Bien 😁', "Error al abrir el archivo ZIP {$filename}.");
            $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode(dirname($zip_file)));
            return false;
        }
    }

    /**
     * Devuelve una cadena de texto con los detalles del servidor web, incluyendo el software y la versión de PHP.
     *
     * @return string
     */
    public function getWebServerDetails(): string
    {
        // Obtener la información del software del servidor desde la variable $_SERVER
        $serverSoftware = $_SERVER["SERVER_SOFTWARE"];

        // Si la variable no está vacía, agregar la versión de PHP al final de la cadena
        if (!empty($serverSoftware)) {
            $serverSoftware = strpos($serverSoftware, "PHP") !== false ? $serverSoftware : $serverSoftware . ' ' . 'PHP/' . PHP_VERSION;
        }

        // Reemplazar los caracteres '+' y '~' por espacios en blanco para unificar el formato de la cadena
        $serverSoftware = str_replace(array('+', '~'), ' ', $serverSoftware);

        // Dividir la cadena en palabras individuales y formatear cada una de ellas con una etiqueta HTML
        $words = explode(' ', $serverSoftware);
        $formattedWords = array_map(function ($word) {
            return '<span class="badge">' . $word . '</span>';
        }, $words);

        // Unir las palabras formateadas en una sola cadena de texto
        $serverDetails = implode(' ', $formattedWords);

        // Limitar la cadena a las primeras cuatro palabras, ya que la información adicional puede no ser relevante o estar incompleta
        $serverDetails = implode(' ', array_slice($formattedWords, 0, 4));

        return $serverDetails;
    }

    /**
     * Función para borrar archivos
     *
     * @param string $filename
     * @return boolean
     */
    public function removeFile(string $filename = ""): bool
    {
        // Comprobamos que es un archivo
        if (file_exists($filename) && is_file($filename)) {
            // Intenta borrar el archivo
            if (unlink($filename)) {
                // Comprobamos si existe
                if (!file_exists($filename)) {
                    return true;
                } else {
                    return false;
                }
            }
        }
    }

    /**
     * Función que permite guardar el contenido de un archivo
     *
     * @param string $filename
     * @param string $data
     * @return boolean
     */
    public function saveContent(string $filename = "", string $data = ""): bool
    {
        // Comprobamos que es un archivo
        if (file_exists($filename) && is_file($filename)) {
            // Guardamos
            file_put_contents($filename, $data);
            // Si se guarda bien enviamos mensaje y redirigimos al mismo sitio
            if (file_get_contents($filename) == $data) {
                return true;
            } else {
                return false;
            }
        }
        return false;
    }

    /**
     * Función que permite mover un archivo de una ubicación a otra.
     * @param string $filename El nombre del archivo a mover.
     * @param string $fileRouteIn La ruta actual del archivo.
     * @param string $fileRouteOut La ruta donde se desea mover el archivo.
     * @return void
     */
    public function moveFiles(string $filename = "", string $fileRouteIn = "", string $fileRouteOut = "")
    {
        // Se construye la ruta del archivo actual.
        $actualFileRoute = ROOT . '/' . $fileRouteIn . '/' . $filename;

        // Verifica si el archivo existe y es un archivo válido.
        if (file_exists($actualFileRoute) && is_file($actualFileRoute)) {
            // Directorio donde se va a mover el archivo
            $outputFile = ROOT . '/' . $fileRouteOut . '/' . $filename;
            // Intenta mover el archivo a la nueva ubicación.
            $result = rename($actualFileRoute, $outputFile);
            // Si se logra mover el archivo, se envía un mensaje de éxito y se redirecciona a la nueva carpeta.
            if ($result) {
                $this->msgSet('Bien 😁', "El archivo {$filename} ha sido movido exitosamente.");
                $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode(dirname($outputFile)));
            }
            // Si no se logra mover el archivo, se envía un mensaje de error y se redirecciona a la nueva carpeta.
            else {
                $this->msgSet('Ups 😪', "Hubo un error y no se ha podido mover el archivo {$filename}");
                $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode(dirname($outputFile)));
            }
        }
    }

    /**
     * Función para mover una carpeta entera.
     *
     * @param string $fileRouteIn Ruta de origen de la carpeta.
     * @param string $fileRouteOut Ruta de destino de la carpeta.
     */
    public function moveDir(string $fileRouteIn = "", string $fileRouteOut = "")
    {
        // Verificamos si la carpeta existe y es un directorio
        if (is_dir($fileRouteIn)) {
            // Creamos la nueva carpeta de destino si no existe
            if (!is_dir($fileRouteOut)) {
                mkdir($fileRouteOut, 0777, true);
            }

            // Obtenemos los archivos y subdirectorios de la carpeta actual
            $files = scandir($fileRouteIn);

            // Recorremos los archivos y subdirectorios
            foreach ($files as $file) {
                // Ignoramos los directorios . y ..
                if ($archivo != '.' && $file != '..') {
                    // Construimos las rutas de origen y destino de cada archivo o subdirectorio
                    $fileRouteInNew = $fileRouteIn . '/' . $file;
                    $fileRouteOutNew = $fileRouteOut . '/' . $file;

                    // Si es un subdirectorio, llamamos a la función de manera recursiva
                    if (is_dir($fileRouteInNew)) {
                        moveDir($fileRouteInNew, $fileRouteOutNew);
                    } else {
                        // Si es un archivo, lo movemos utilizando la función rename()
                        rename($fileRouteInNew, $fileRouteOutNew);
                    }
                }
            }

            // Borramos la carpeta original después de haber movido todos los archivos y subdirectorios
            rmdir($fileRouteIn);
            // Enviamos mensaje
            $this->msgGet('Bien 😁', 'La carpeta se ha movido correctamente.');
            // Redireccionamos a la nueva carpeta
            $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode(dirname($fileRouteOut)));
        } else {
            // Enviamos mensaje
            $this->msgGet('Ups 😪', 'La carpeta especificada no existe o no es un directorio.');
            // Redireccionamos a la nueva carpeta
            $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode(dirname($fileRouteOut)));
        }
    }

    /**
     * Función para comprobar si la carpeta es el directorio raiz
     *
     * @param string $url La URL a comprobar.
     * @return bool Devuelve true si la URL es el directorio raiz.
     */
    public function isRoot(string $dir = ""): bool
    {
        // Comprobar si la carpeta es el directorio raiz
        if ($dir == ROOT) {
            return true;
        }
        // Si no se encontró el archivo, retornar false
        return false;
    }

    /**
     * Quitamos todo lo que sea locahost:8080/[nombre].php  y lo dejamos en localhost:8080
     *
     * @param string $url La URL de entrada que se analizará y se modificará.
     * @return string La nueva URL sin diagonales invertidas dobles en su ruta.
     */
    public function parseUrl(string $url): string
    {
        // Obtenemos el nombre de host sin / al final
        $host = rtrim($_SERVER['HTTP_HOST'], '\\/');
        // Comprobamos https o http
        $https = (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on') ? 'https://' : 'http://';
        // Combinamos el nombre de host y el número de puerto en la URL base
        $baseUrl = $https . $host;
        // Buscamos la posición de la URL base en la URL completa
        $baseUrlPosition = strpos($url, $baseUrl);
        // Si la URL base se encuentra, devolvemos solo la parte de la URL que se encuentra antes de la URL base
        if ($baseUrlPosition !== false) {
            return substr($url, 0, $baseUrlPosition + strlen($baseUrl));
        }
        // Si la URL base no se encuentra, devolvemos la URL completa sin cambios
        return $url;
    }

    /**
     * Sanitiza el contenido
     *
     * @param string $filePath
     * @return string
     */
    public function sanitizeFileContents(string $filePath = ""): string
    {
        // Obtiene el contenido del archivo
        $fileContents = file_get_contents($filePath);

        // Sanitiza el contenido con htmlspecialchars
        $sanitizedContents = htmlspecialchars($fileContents, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        // Devuelve el contenido sanitizado
        return $sanitizedContents;
    }

    /**
     * Comprobar si es una imagen
     *
     * @param string $ext  // Parámetro opcional que indica la extensión de archivo a verificar
     * @return bool  // Devuelve un valor booleano true si es una imagen, false si no lo es
     */
    public function checkIsImage(string $ext = ""): bool
    {
        // Array que contiene las extensiones de archivo comunes de imágenes
        $imageExtensions = $this->getOption('imageSupport');

        // Verificar si la extensión proporcionada está presente en el array de extensiones de imágenes
        if (in_array($ext, $imageExtensions)) {
            return true; // Es una imagen
        } else {
            return false; // No es una imagen
        }
    }

    /**
     * Comprobar si es editable
     *
     * @param string $ext  // Parámetro opcional que indica la extensión de archivo a verificar
     * @return bool  // Devuelve un valor booleano true si el archivo es editable, false si no lo es
     */
    public function checkIsEditable(string $ext = ""): bool
    {
        // Array que contiene las extensiones de archivo comunes de archivos editables
        $editableExtensions = $this->getOption('editableFilesSupport');

        // Verificar si la extensión proporcionada está presente en el array de extensiones de archivos editables
        if (in_array($ext, $editableExtensions)) {
            return true; // Es un archivo editable
        } else {
            return false; // No es un archivo editable
        }
    }

    /**
     * Obtener información de los datos en formato JSON y devolverla como HTML con una etiqueta de detalles plegable.
     *
     * @param array $data Los datos que se van a depurar en formato de array.
     * @param bool $isFile Un booleano que indica si se está depurando un archivo o un array.
     * @param string $filename El nombre del archivo que se va a depurar (sólo si $isFile es true).
     * @return string La salida HTML que muestra la información depurada.
     */
    public function debug(array $data = [], bool $isFile = false, string $filename = ""): string
    {
        // Codifica los datos como JSON con una presentación agradable y con caracteres Unicode y barras invertidas sin escapar.
        $output = json_encode($data, JSON_PRETTY_PRINT, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);

        // Si se está depurando un archivo, resalta su código fuente; de lo contrario, resalta el JSON y envuelve todo en una etiqueta.
        $output = ($isFile) ? highlight_file($filename, true) : highlight_string('<?php' . PHP_EOL . $output . PHP_EOL . '?>', true);

        // Crea la salida HTML para la depuración.
        $html = <<<HTML
            <details class="debug" style="padding:0;margin:20px auto;">
                <summary>Debug</summary>
                    <div class="details-body ">
                        <pre class="p-1 bg-light border">
                            {$output}
                        </pre>
                    </div>
            </details>
        HTML;

        // Devuelve la salida HTML.
        return $html;
    }

    /**
     * $_POST
     *
     * @param string $key
     * @return string
     */
    public function getPost(string $key, bool $sanitize = true): string
    {
        //comprobar si una cadena de texto contiene sólo caracteres alfanuméricos (letras y números).
        if ($sanitize && !ctype_alnum($key) || empty($key)) {
            return "";
        }
        // Validar y filtrar $_POST[$key]
        $value = filter_input(INPUT_POST, $key, FILTER_SANITIZE_SPECIAL_CHARS);
        // Decodificar el valor de la variable si es necesario
        $value = urldecode($value);
        // Codificar los caracteres especiales en entidades HTML
        $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        // Eliminar los espacios en blanco al inicio y al final del valor
        $value = trim($value);
        // Comprobamos si $sanitize es true y sino lo pasamos normal
        // Válido para cuando queramos editar archivos sin perder datos
        return ($sanitize) ? $value : (isset($_POST[$key]) ? $_POST[$key] : "");
    }

    /**
     * $_GET
     *
     * @param string $key
     * @return string
     */
    public function get(string $key): string
    {
        // Verificar si $key es válido
        if (!ctype_alnum($key) || empty($key)) {
            return "";
        }
        // Validar y filtrar $_GET[$key]
        $value = filter_input(INPUT_GET, $key, FILTER_SANITIZE_FULL_SPECIAL_CHARS, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH | FILTER_FLAG_STRIP_BACKTICK | FILTER_FLAG_NO_ENCODE_QUOTES);
        // Decodificar el valor de la variable si es necesario
        $value = urldecode($value);
        // Codificar los caracteres especiales en entidades HTML
        $value = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        // Eliminar los espacios en blanco al inicio y al final del valor
        $value = trim($value);
        return $value;
    }

    /**
     * Convierte un tamaño de archivo en Bytes a una unidad de medida más legible para el usuario, como KB, MB, GB o TB.
     *
     * @param int $size Tamaño del archivo en Bytes.
     * @return string Tamaño del archivo con la unidad de medida correspondiente.
     */
    public function formatFileSize($size)
    {
        // Array de unidades de medida
        $units = array('Bytes', 'KB', 'MB', 'GB', 'TB');
        // Calcula la potencia de la base 1024 necesaria para obtener la unidad de medida correcta
        // Utiliza un operador ternario para verificar si el tamaño del archivo es mayor a cero
        $power = $size > 0 ? floor(log($size, 1024)) : 0;
        // Divide el tamaño del archivo por la cantidad resultante de 1024 elevado a la potencia obtenida para obtener el tamaño en la unidad de medida correcta
        $result = number_format($size / pow(1024, $power), 2, '.', ',');
        // Concatena el resultado de la división y la unidad de medida correspondiente, obtenida del array de unidades utilizando el valor de la variable $power como índice
        return $result . ' ' . $units[$power];
    }

    /**
     * Genera el breadcrumb en formato HTML
     *
     * @param string $path La ruta del directorio actual
     * @param string $root La ruta de la carpeta raíz
     * @return string El breadcrumb en formato HTML
     */
    public function createBreadcrumb(string $path = "", string $root = ""): string
    {
        // Separamos las carpetas de la ruta
        $folders = explode('/', str_replace($root, '', $path));
        // Iniciamos el breadcrumb con el enlace a la carpeta raíz
        $breadcrumb = '<nav aria-label="breacrumb"><ol class="breadcrumb"><li class="breadcrumb-item active" aria-current="page"><a class="text-decoration-none text-black" href="' . $this->getOption('Site_url') . '">Inicio</a></li>';
        // Creamos los enlaces a cada carpeta
        $route = '';
        foreach ($folders as $folder) {
            if (!empty($folder)) {
                $route .= '/' . $folder;
                $breadcrumb .= '<li class="breadcrumb-item"><a class="text-dark text-decoration-none" href="' . $this->getOption('Site_url') . '?get=dir&name=' . base64_encode(ROOT . $route) . '">' . $folder . '</a></li>';
            }
        }
        // Cerramos el breadcrumb
        $breadcrumb .= '</ol></nav>';
        return $breadcrumb;
    }

    /**
     * Error no encontrado
     *
     * @param mixed $msg  // Mensaje de error a mostrar
     * @param bool $code  // Código de estado HTTP para devolver en la respuesta
     * @return void
     */
    public function error($msg, $code = false)
    {
        // Si se proporciona un código de estado HTTP, establecerlo en la respuesta
        if ($code) {
            http_response_code($code);
        }
        // Configurar encabezados para evitar el almacenamiento en caché de la respuesta
        header('content-type: text/html');
        header('Expires: ' . gmdate('D, d M Y H:i:s') . ' GMT');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0');
        header('Cache-Control: post-check=0, pre-check=0', false);
        header('Pragma: no-cache');
        // Salir de la ejecución del script y mostrar el mensaje de error al usuario
        exit('<h2>Error</h2>' . $msg);
    }

    /**
     * Redirecciona a una URL.
     *
     * @param string $url  La URL a la que se redireccionará.
     * @param int $st      El código de estado HTTP a utilizar (por defecto, 302).
     * @param int $wait    El tiempo de espera antes de redireccionar (en segundos).
     */
    public function redirect($url, $st = 302, $wait = 0)
    {
        // Convertir $url y $st a tipos de datos apropiados
        $url = (string)$url;
        $st = (int)$st;
        // Definir mensajes para los códigos de estado HTTP
        $msg = [
            301 => '301 Movido permanentemente',
            302 => '302 Encontrado',
        ];
        // Verificar si las cabeceras ya han sido enviadas
        if (headers_sent()) {
            // Si las cabeceras ya han sido enviadas, redireccionar mediante JavaScript
            echo "<script>document.location.href='" . $url . "';</script>\n";
        } else {
            // Si las cabeceras no han sido enviadas, configurar la cabecera HTTP y redireccionar mediante PHP
            header('HTTP/1.1 ' . $st . ' ' . ($msg[$st] ?? '302 Found'));
            if ($wait > 0) {
                sleep($wait);
            }
            header("Location: {$url}");
            exit(0);
        }
    }

    /**
     * Elimina caracteres especiales y acentos de un texto
     *
     * @param string $texto Texto a limpiar
     * @return string Texto limpio
     */
    public function cleanName(string $txt): string
    {
        $txt = strtolower($txt); // Convierte el texto a minúsculas
        $txt = str_replace(" ", "-", $txt); // Reemplaza los espacios por guiones
        $txt = preg_replace("/[^a-z0-9-]+/", "", $txt); // Elimina caracteres especiales y acentos
        $txt = trim($txt, "-"); // Elimina guiones al principio y al final
        $txt = preg_replace("/-{2,}/", "-", $txt); // Elimina guiones duplicados
        // Asegurarse de que la cadena no sea demasiado larga
        $max_length = 50;
        if (strlen($txt) > $max_length) {
            $txt = substr($txt, 0, $max_length);
        }
        return $txt;
    }

    /**
     * Elimina un directorio y su contenido de forma recursiva.
     *
     * @param string $directorio La ruta del directorio que se eliminará.
     * @return int El número de archivos y directorios eliminados con éxito.
     * @throws Exception Si no se puede leer el directorio o si se producen errores al eliminar el directorio.
     */
    public function removeDir(string $dir = ""): int
    {
        // Verifica si el directorio es legible
        if (!is_readable($dir)) {
            throw new Exception("No se puede leer el directorio: $dir");
        }
        // Contadores para el número de archivos y directorios eliminados con éxito y errores
        $success = 0;
        $fail = 0;

        // Obtiene una lista de archivos y directorios en el directorio, excluyendo "." y ".."
        $files = array_diff(scandir($dir), array('.', '..'));
        // Itera a través de cada archivo y directorio en el directorio
        foreach ($files as $file) {
            // Construye la ruta completa del archivo o directorio
            $filedir = $dir . DIRECTORY_SEPARATOR . $file;
            // Si el archivo es un directorio, llama a la función $this->removeDir() de forma recursiva
            if (is_dir($filedir)) {
                try {
                    $this->removeDir($filedir);
                    $success++;
                } catch (Exception $e) {
                    // Si se produce un error, aumenta el contador de errores
                    $fail++;
                }
            } else {
                // Si el archivo es un archivo, intenta eliminarlo
                if (unlink($filedir)) {
                    $success++;
                } else {
                    // Si se produce un error, aumenta el contador de errores
                    $fail++;
                }
            }
        }
        // Intenta eliminar el directorio
        if (rmdir($dir)) {
            $success++;
        } else {
            // Si se produce un error, aumenta el contador de errores
            $fail++;
        }
        // Si se produjeron errores, lanza una excepción
        if ($fail > 0) {
            throw new Exception("Se produjeron errores al eliminar el directorio: $dir");
        }
        // Devuelve el número de archivos y directorios eliminados con éxito
        return $success;
    }

    /**
     * Crea una carpeta en el directorio especificado
     *
     * @param string $dir Directorio donde crear la carpeta
     * @param string $name Nombre de la carpeta
     * @return bool true si se crea correctamente, false en caso contrario
     */
    public function createDir(string $dir = "", string $name = ""): bool
    {
        $folderName = $dir . '/' . $name;
        if (!file_exists($folderName)) {
            mkdir($folderName, 0777, true);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Crea un archivo en el directorio especificado
     *
     * @param string $dir Directorio donde crear el archivo
     * @param string $name Nombre del archivo
     * @return bool true si se crea correctamente, false en caso contrario
     */
    public function createFile(string $dir = "", string $name = ""): bool
    {
        $folderName = $dir . '/' . $name;
        if (!file_exists($folderName)) {
            // Obtenemos la extension
            $extension = pathinfo($folderName, PATHINFO_EXTENSION);
            // Comprobamos que es editable y lleva extension
            if ($extension && in_array($extension, $this->getOption('editableFilesSupport'))) {
                $archivo = fopen($folderName, "w") or die("No se pudo crear el archivo.");
                $texto = "El archivo ha sido creado.";
                fwrite($archivo, $texto);
                fclose($archivo);
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

}

/**
 * Trait FilesystemInfo
 * Este trait proporciona información de carpetas y archivos.
 *
 * getDirInfo: Obtener las carpetas y archivos.
 * getFileInfo: Obtener la información del archivo.
 * @package MediaManager
 * @category Trait
 */
trait FilesystemInfo
{

    /**
     * Obtener las carpetas y archivos
     *
     * @param [type] $dir
     * @return array
     */
    public function getDirInfo($dir): array
    {
        // Verificar si la ruta es un directorio
        if (is_dir($dir)) {
            // Si la ruta es un directorio, abrimos el directorio
            if ($dh = opendir($dir)) {
                // Creamos un arreglo vacío para almacenar la información de los archivos y directorios
                $result = [];
                // Obtenemos la ruta del directorio raíz
                $root = str_replace(ROOT, '', $dir);
                // Leemos el directorio
                while (($file = readdir($dh)) !== false) {
                    // No enseñar esto: Saltar archivos ocultos como .htaccess, .git y .gitignore que hay en la opcion exclude
                    if (in_array(basename($file), $this->getOption('exclude'))) {
                        continue;
                    }
                    // Si el archivo no es un archivo oculto
                    if ($file != '.' && $file != '..') {
                        // Si el archivo es un directorio
                        if (is_dir($dir . '/' . $file)) {
                            // Agregamos información sobre el directorio al arreglo de resultados
                            $result[] = [
                                'filepath' => $root . '/' . $file,
                                'filename' => $file,
                                'filetype' => 'dir',
                                'fileext' => false,
                            ];
                        } else {
                            // Si el archivo no es un directorio, obtenemos información adicional sobre el archivo
                            $file_info = pathinfo($root . '/' . $file);
                            // Si el archivo tiene una extensión
                            if (isset($file_info['extension'])) {
                                // Obtenemos la extensión del archivo
                                $file_info = pathinfo($root . '/' . $file);
                                $file_extension = $file_info['extension'];
                                // Agregamos información sobre el archivo al arreglo de resultados
                                $result[] = [
                                    'filepath' => $root . '/' . $file,
                                    'filename' => $file,
                                    'filetype' => 'file',
                                    'fileext' => $file_extension,
                                ];
                            } else {
                                // Si el archivo no tiene una extensión, lo tratamos como un archivo de código
                                $result[] = [
                                    'filepath' => $root . '/' . $file,
                                    'filename' => $file,
                                    'filetype' => 'file',
                                    'fileext' => "code",
                                ];
                            }
                        }
                    }
                }
                // Cerramos el directorio
                closedir($dh);
                // Devolvemos el arreglo de resultados
                return $result;
            }
        }
        // Si la ruta no es un directorio, devolvemos un array vacio
        return [];
    }

    /**
     * Obtener la información del archivo
     *
     * @param string $filename Ruta y nombre del archivo a obtener información
     * @return array|false Array con información del archivo o false si no se puede obtener la información
     */
    public function getFileInfo(string $filename = "")
    {
        if (is_dir($filename) || is_file($filename)) {
            // Obtenemos el tamaño del archivo en bytes
            $filesize = filesize($filename);
            // Obtenemos la fecha de modificación del archivo en formato Unix timestamp
            $filedate = filemtime($filename);
            // Obtenemos los permisos del archivo en octal
            $fileperms = fileperms($filename);
            // Devolvemos un array con la información del archivo
            return [
                'filepath' => $filename, // Ruta y nombre del archivo
                'fileinfo' => pathinfo($filename), // Información del archivo (nombre, extensión, directorio, etc.)
                'fileperms' => decoct($fileperms&0777), // Permisos del archivo en octal
                'filesize' => $this->formatFileSize($filesize), // Tamaño del archivo en bytes
                'filedate' => date("d-m-Y H:i:s", $filedate), // Fecha de modificación del archivo en formato humano
            ];
        }
        return [];
    }

}

/**
 * Trait HtmlView
 * Este trait proporciona funciones para imprimir el html en la página.
 *
 * cssStructureByDefault: Structura css por defecto.
 * generateHead:Generamos el head.
 * generateHeader:Generamos el header.
 * generateFooter:Generamos el footer.
 * generateScripts:Generamos el scripts.
 * generateLayout:Generamos el layout.
 * defaultView: Generamos la vista por defecto.
 * editView: Generamos la vista de editar.
 * uploadFormView: Generamos la vista de subir archivos.
 * createDirView: Generamos la vista de crear directorio.
 * removeDirView: Generamos la vista de borrar directorio.
 * loginView: Generamos la vista del login.
 *
 * @package MediaManager
 * @category Trait
 */
trait HtmlView
{

    /**
     * Generamos el head
     *
     * @param string $otherCss css
     * @return string
     */
    public function generateHead(string $otherCss = ""): string
    {
        $title = $this->getOption('title'); // Título del sitio web

        $links = '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootswatch@5.2.3/dist/sandstone/bootstrap.min.css" />';
        // Si estamos en la vista de edicion cargamos CodeMirror
        if (array_key_exists('get', $_GET) && $this->get('get') == 'file') {
            $links .= '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.css" />';
            $links .= '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/theme/material-darker.min.css" integrity="sha512-2OhXH4Il3n2tHKwLLSDPhrkgnLBC+6lHGGQzSFi3chgVB6DJ/v6+nbx+XYO9CugQyHVF/8D/0k3Hx1eaUK2K9g==" crossorigin="anonymous" referrerpolicy="no-referrer" />';
        }
        // Retornar la sección head del HTML
        return <<<HTML
            <head>
                <meta charset="utf-8"><title>{$title}</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <meta name="application-name" content="AntCMS" />
                <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
                <meta http-equiv="Pragma" content="no-cache">
                <meta http-equiv="Expires" content="0">
                <meta name="referrer" content="no-referrer-when-downgrade">
                <meta name="robots" content="noindex,nofollow">
                {$links}
                <style rel="stylesheet">img{max-width:100%;}.btn svg{width:22px;height:22px;fill:var(--bs-dark);display:flex;justify-content:center;align-items:center;margin:0;padding:3px}.btn-primary svg,.btn-dark svg,.btn-danger svg,.btn-secondary svg{fill:var(--bs-light)}</style>
                <style rel="stylesheet">{$otherCss}</style>
            </head>
        HTML;
    }

    /**
     * Generamos el header
     *
     * @param string $url url de la web
     * @param string $title titulo
     * @param string $logo logo
     * @param string $homeIcon icono de home
     * @param string $logoutTpl plantilla de e enlace de logout
     * @return string
     */
    public function generateHeader(string $url, string $title, string $logo, string $homeIcon, string $logoutTpl): string
    {
        $urlHome = ($this->isLogin()) ? '<a class="nav-link" href="' . $url . '">Inicio</a>' : '';
        $urlGeneratePass = ($this->isLogin()) ? '<a class="nav-link" href="' . $url . '?generar=password">Generar</a>' : '';
        return <<<HTML
            <header class="header">
                <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                    <div class="container-fluid">
                        <a class="navbar-brand" href="{$url}">
                            <img class="rounded-pill" src="{$logo}" alt="logo">
                            <span>{$title}</span>
                        </a>
                        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavAltMarkup" aria-controls="navbarNavAltMarkup" aria-expanded="false" aria-label="Toggle navigation">
                            <span class="navbar-toggler-icon"></span>
                        </button>
                        <div class="collapse navbar-collapse" id="navbarNavAltMarkup">
                            <div class="navbar-nav ms-auto mb-2 mb-lg-0">
                                {$urlHome}
                                {$urlGeneratePass}
                                {$logoutTpl}
                            </div>
                        </div>
                    </div>
                </nav>
            </header>
        HTML;

    }

    /**
     * Generamos el footer
     *
     * @return string
     */
    public function generateFooter(): string
    {
        $year = date('Y');
        return <<<HTML
            <footer class="footer mt-4 text-center">
                <div class="container-fluid">
                    <div class="row">
                        <div class="col-md-12">
                            <p class="copyright">Moncho Varela © {$year}</p>
                        </div>
                    </div>
                </div>
            </footer>
        HTML;
    }

    /**
     * Generamos el html del javascript
     *
     * @param string $js
     * @return string
     */
    public function generateScripts(string $js): string
    {

        // imprimimos la session
        $session = $this->msgGet('msg');
        $scripts = '<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script>';
        // Si estamos en la vista de edicion cargamos CodeMirror
        if (array_key_exists('get', $_GET) && $this->get('get') == 'file') {
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.js" integrity="sha512-8RnEqURPUc5aqFEN04aQEiPlSAdE0jlFS/9iGgUyNtwFnSKCXhmB6ZTNl7LnDtDWKabJIASzXrzD0K+LYexU9g==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/markdown/markdown.js" integrity="sha512-HO6T6BeQvqVauqK9yn7/pkoiaaowmxIbN0Q15kjsM/8oJJ3seJI0/DlEqlEosGrpNkhPowUkV9hvrVtB+rqoDw==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/htmlmixed/htmlmixed.min.js" integrity="sha512-HN6cn6mIWeFJFwRN9yetDAMSh+AK9myHF1X9GlSlKmThaat65342Yw8wL7ITuaJnPioG0SYG09gy0qd5+s777w==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/css/css.min.js" integrity="sha512-rQImvJlBa8MV1Tl1SXR5zD2bWfmgCEIzTieFegGg89AAt7j/NBEe50M5CqYQJnRwtkjKMmuYgHBqtD1Ubbk5ww==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/javascript/javascript.min.js" integrity="sha512-I6CdJdruzGtvDyvdO4YsiAq+pkWf2efgd1ZUSK2FnM/u2VuRASPC7GowWQrWyjxCZn6CT89s3ddGI+be0Ak9Fg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/php/php.min.js" integrity="sha512-jZGz5n9AVTuQGhKTL0QzOm6bxxIQjaSbins+vD3OIdI7mtnmYE6h/L+UBGIp/SssLggbkxRzp9XkQNA4AyjFBw==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/xml/xml.min.js" integrity="sha512-LarNmzVokUmcA7aUDtqZ6oTS+YXmUKzpGdm8DxC46A6AHu+PQiYCUlwEGWidjVYMo/QXZMFMIadZtrkfApYp/g==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
            $scripts .= '<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/mode/clike/clike.min.js" integrity="sha512-l8ZIWnQ3XHPRG3MQ8+hT1OffRSTrFwrph1j1oc1Fzc9UKVGef5XN9fdO0vm3nW0PRgQ9LJgck6ciG59m69rvfg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>';
        }
        $scripts .= '<script rel="javascript">
                function message(title,msg){
                    const html =  `<div class="toast show fixed-top m-2" role="alert" aria-live="assertive" aria-atomic="true" id="msg-notification">
                        <div class="toast-header">
                            <span class="bg-primary p-1 rounded-pill mx-2" style="width:5px;height:5px;"></span>
                            <strong class="me-auto">${title}</strong>
                        </div>
                        <div class="toast-body">${msg}</div>
                    </div>`;
                    document.body.innerHTML += html;
                    let w = setTimeout(() => {
                        document.getElementById("msg-notification").remove();
                        clearTimeout(w);
                    },2000);
                }
            </script>';
        $scripts .= '<script rel="javascript">' . $js . '</script>';
        $scripts .= $session;
        return $scripts;
    }

    /**
     * Layout html
     *
     * @param string $content // Contenido que se va a incluir en el layout
     * @param string $css // Ruta al archivo CSS que se va a incluir
     * @param string $js // Ruta al archivo JavaScript que se va a incluir
     * @return string // El HTML del layout
     */
    public function generateLayout(string $content = "", string $css = "", string $js = "", string $current = ""): string
    {

        $url = $this->getOption('Site_url'); // URL del sitio web
        $title = $this->getOption('title'); // Título del sitio web
        $logo = $this->getOption('logo'); // Logo del sitio web
        $homeIcon = $this->icon('home'); // Icono
        // Carpeta donde se subirán archivos, si está definida
        $folderToUpload = ($current) ? base64_encode($current) : '';
        // Llamamos a la función createBreadcrumb
        $breadcrumb = $this->createBreadcrumb($current, ROOT);
        // boton de logout que solo sale si estamos logueados
        $logoutTpl = ($this->isLogin()) ? '<a class="nav-link" href="' . $url . '?logout=true">Salir</a>' : '';
        // Llamamos a la función generateHead
        $head = $this->generateHead($css);
        // Llamamos a la función generateHeader
        $header = $this->generateHeader($url, $title, $logo, $homeIcon, $logoutTpl);
        // Llamamos a la función generateFooter
        $footer = $this->generateFooter();
        // Llamamos a la función generateScripts
        $scripts = $this->generateScripts($js);
        // plantilla html
        return <<<HTML
            <!Doctype html>
            <html lang="es">
                {$head}
                <body id="top" data-theme="light">
                    <main id="app">
                        {$header}
                        <section class="container-fluid py-3 pb-1">
                            <div class="row">
                                <div class="col-md-12">{$breadcrumb}</div>
                            </div>
                        </section>
                        <section class="container-fluid">
                            {$content}
                        </section>
                        {$footer}
                    </main>
                    {$scripts}
                </body>
            </html>
        HTML;
    }

    /**
     * Función que devuelve una vista predeterminada para mostrar el contenido de un directorio.
     *
     * @param string $dir Directorio a mostrar.
     * @param array $arr Array opcional con información adicional para mostrar en la vista.
     * @return string HTML con la vista generada.
     */
    public function defaultView(string $dir = ROOT, array $arr = []): string
    {
        $url = $this->getOption('Site_url');
        // Obtener información del directorio
        $scanDir = $this->getDirInfo($dir);
        // Inicializar variable para el HTML generado
        $html = '<div class="btn-group">';

        // Comprobamos que no estamos en root y añadimos el boton volver y los demas botones
        $urlCreateFolder = $url . '?create=dir&where=' . base64_encode($dir);
        $urlCreateFile = $url . '?create=file&where=' . base64_encode($dir);
        $urlUploadFile = $url . '?get=upload&name=' . base64_encode($dir);

        // Comprobamos si estamos en root
        $inRoot = ($this->isRoot($dir)) ? false : true;

        // Si no estamos en root, añadimos el botón para volver y el botón para borrar carpeta
        if ($inRoot) {
            $backToUrl = $url . '?get=dir&name=' . base64_encode(dirname($dir));
            $urlDeleteFolder = $url . '?delete=dir&where=' . base64_encode($dir);
            $html .= '<a class="btn btn-primary" href="' . $backToUrl . '" title="Volver">' . $this->icon('back') . '</a>';
            $html .= '<a class="btn btn-danger" href="' . $urlDeleteFolder . '" title="Borrar carpeta">' . $this->icon('trash') . '</a>';
        }

        // Generamos los botones según si estamos en root o no
        $html .= '<a class="btn btn-dark" href="' . $urlUploadFile . '" title="Subir archivo">' . $this->icon('upload') . '</a>';
        $html .= '<a class="btn btn-dark" href="' . $urlCreateFolder . '" title="Crear carpeta">' . $this->icon('folder') . '</a>';
        $html .= '<a class="btn btn-dark" href="' . $urlCreateFile . '" title="Crear archivo">' . $this->icon('plus') . '</a>';

        $html .= '</div>';
        // Agregar contenedor para mostrar los archivos/directorios
        $html .= '<div class="row gy-3 gx-1 my-1">';
        // Si hay archivos/directorios en el directorio, mostrarlos
        $html .= (count($scanDir) > 0) ? "" : "No hay ningún archivo en esta carpeta.";
        foreach ($scanDir as $item) {

            $filepath = base64_encode(ROOT . $item['filepath']);
            $filename = $item['filename'];
            $filetype = $item['filetype'];
            $fileext = $item['fileext'];

            $icon = $this->icon('folder');
            if ($filetype == 'file') {
                list("isValid" => $isValid, "extType" => $extType) = $this->checkExtension($fileext);
                $icon = $this->renderIconByType($extType, $fileext, $filetype);
            }

            // Agregar enlace al archivo/directorio
            $html .= <<<HTML
                <div class="col-6 col-sm-4 col-md-3 col-lg-2">
                    <a class="text-decoration-none file" href="{$url}/?get={$filetype}&name={$filepath}">
                        <div class="card border-light shadow">
                            <div class="card-body p-2 py-3 bg-white position-relative">
                                {$icon}
                            </div>
                            <div class="card-footer bg-dark text-light text-truncate"><span>{$filename}</span></div>
                        </div>
                    </a>
                </div>
            HTML;
        }

        // Cerrar contenedor
        $html .= '</div>';
        // Detalles del servidor
        $serverDetails = $this->getWebServerDetails();
        $html .= '<div class="server-details">' . $serverDetails . '</div>';
        // Generamos la plantilla por defecto
        return $this->generateLayout($html, '.card-body svg{width:50px;height:50px;margin:auto;display:flex;fill:var(--bs-dark);}.file{transition: all 500ms ease;}.file:hover,.file:focus{opacity:0.8;transition: all 500ms ease;}', '', $dir);
    }

    /**
     * Esta función genera la vista de edición de un archivo o directorio.
     *
     * @param string $dir Ruta del archivo o directorio a editar.
     * @param array $arr Arreglo de datos adicionales.
     *
     * @return string Retorna una cadena con el código HTML generado.
     */
    public function editView(string $dir = ROOT, array $arr = []): string
    {
        $url = $this->getOption('Site_url');
        $fileInfo = $this->getFileInfo($dir);
        // Obtener información del archivo
        $fileperms = $fileInfo['fileperms'];
        $filename = $fileInfo['fileinfo']['filename'];
        $extension = pathinfo($dir, PATHINFO_EXTENSION) ? $fileInfo['fileinfo']['extension'] : '';
        $filesize = $fileInfo['filesize'];
        $filedate = $fileInfo['filedate'];
        // Obtener la ruta de la carpeta actual
        $currentFolder = str_replace($filename . '.' . $extension, '', $dir);
        $html = "";
        // Comprobamos que no estamos en root y añadimos el boton volver
        if (array_key_exists('get', $_GET)) {
            $backToUrl = $url . '?get=dir&name=' . base64_encode(dirname($dir));
            $html .= '<a class="btn btn-sm btn-dark mb-2" href="' . $backToUrl . '" title="Volver">' . $this->icon('back') . '</a>';
        }
        // Generar el contenido según el tipo de archivo
        $content = "";
        $buttons = "";
        $img = "";
        $download = "";
        // Generar el contenido según el tipo de archivo
        list("isValid" => $isValid, "extType" => $extType) = $this->checkExtension($extension);

        // Si en la url hay un 'root.php' o un 'gallery.php' lo quitamos
        $src = $this->parseUrl($this->getOption('Site_url')) . str_replace(ROOT, '', $dir);

        $download = '';
        $openExternal = '';
        $contentMap = [
            'isAudio' => '<figure class="bg-dark text-light p-0 m-0 d-flex justify-content-center align-items-center h-100"><audio loading=lazy controls src="' . $src . '"/></figure>',
            'isImage' => '<figure class="bg-dark p-0 m-0 h-100 d-flex justify-content-center align-items-center"><img loading=lazy src="' . $src . '"/></figure>',
            'isVideo' => '<figure class="p-0 m-0 ratio ratio-16x9 bg-dark"><video loading=lazy controls src="' . $src . '" style="aspect-ratio:16/9"/></figure>',
            'isEditable' => '<textarea name="editor" id="editor">' . $this->sanitizeFileContents($dir) . '</textarea>',
            'nonEditable' => '<div class="ratio ratio-1x1"><iframe loading=lazy src="' . $src . '"></iframe></div>',
        ];

        // Imprime el icono depende del tipo en los archivos no editables
        $icon = $this->renderIconByType($extType, $extension, "file");

        // Comprueba el tipo de extension y enseña el contenido
        if (array_key_exists($extType, $contentMap)) {
            // Comprobamos si la extension es pdf, editable, si es imagen y si es video
            $content = ($extension == 'pdf' || $extType == 'isEditable' || $extType == 'isImage' || $extType == 'isVideo' || $extType == 'isAudio') ? $contentMap[$extType] : '<div class="no-preview bg-dark h-100 d-flex justify-content-center align-items-center">' . $icon . '</div>';
            // Comprobamos si los permisos del archivo son 666 o 644 si es no editable, si es imagen o si es video
            $download = ($extType == 'nonEditable' || $extType == 'isImage' || $extType == 'isVideo' || $extType == 'isAudio') ? true : false;
            // Comprobamos si no tiene los permisos 666 o 644 si es editable, si es imagen o si es video
            $openExternal = ($extType == 'isEditable' || $extType == 'isImage' || $extType == 'isVideo' || $extType == 'isAudio') ? true : false;
        } else {
            $content = '<div class="no-preview bg-dark h-100 d-flex justify-content-center align-items-center">' . $icon . '</div>';
        }

        // Download files
        $downloadTpl = ($download) ? '<a class="btn btn-sm btn-dark" href="' . $src . '" download title="Descargar">' . $this->icon('download') . '</a>' : '';
        $openExternalTpl = ($openExternal) ? '<a class="btn btn-sm btn-primary" rel="noopener" target="_blank" href="' . $src . '" title="Abrir en ventana externa">' . $this->icon('external') . '</a>' : '';

        // Crear variable para mensaje de confirmación común
        $confirmMessage = "Va a renombrar el archivo {$filename}, ¿está seguro?";
        // Crear variable para HTML común en la sección "Renombrar"
        $renameHtml = <<<HTML
        <li class="list-group-item">
            <details>
                <summary>Renombrar</summary>
                <div class="details-body py-2">
                    <input type="hidden" name="oldRenameDir" value="{$dir}"/>
                    <input type="hidden" name="oldRenameFile" value="{$filename}.{$extension}"/>
                    <div class="input-group mb-3">
                        <input type="text" class="form-control" name="newRenameFile" value="{$filename}"/>
                        <input type="submit" class="btn btn-sm btn-primary" onclick="return confirm('{$confirmMessage}')" name="rename" value="Renombrar"/>
                    </div>
                </div>
            </details>
        </li>
        HTML;
        $folderDir = dirname(str_replace(ROOT . '/', '', $dir));
        $confirmMessageMoveFiles = "Va a mover el archivo {$filename}.{$extension}, ¿está seguro?";
        // Crear una variable para HTML común en la seccion "Mover archivos"
        $moveFilesHtml = <<<HTML
        <li class="list-group-item">
            <details>
                <summary>Mover archivos</summary>
                <div class="details-body py-2">
                    <input type="hidden" name="old" value="{$folderDir}"/>
                    <input type="hidden" name="filename" value="{$filename}.{$extension}"/>
                    <div class="input-group mb-3">
                        <input type="text" class="form-control" name="new" value="{$folderDir}"/>
                        <input type="submit" class="btn btn-sm btn-primary" onclick="return confirm('{$confirmMessage}')" name="move" value="Mover archivo"/>
                    </div>
                </div>
            </details>
        </li>
        HTML;
        // Mensaje para descomprimir
        $confirmMessageUnzipFiles = "Va a descomprimir el archivo {$filename}.{$extension}, ¿está seguro?";
        $unZipFiles = <<<HTML
            <li class="list-group-item">
                <details open>
                    <summary>Descomprimir archivos</summary>
                    <div class="details-body py-2">
                        <input type="hidden" name="oldDirFile" value="{$folderDir}"/>
                        <input type="hidden" name="fileZipname" value="{$filename}.{$extension}"/>
                        <div class="input-group mb-3">
                            <input type="text" class="form-control" name="newDirFile" value="{$folderDir}"/>
                            <input type="submit" class="btn btn-sm btn-primary" onclick="return confirm('{$confirmMessageUnzipFiles}')" name="unzip" value="Descomprimir archivos"/>
                        </div>
                    </div>
                </details>
            </li>
        HTML;

        if ($extType == 'isImage' || $extType == 'isVideo' || $extType == 'nonEditable') {
            $buttons = $renameHtml . $moveFilesHtml . <<<HTML
            <li class="list-group-item">
                <details class="danger">
                    <summary>Borrar</summary>
                    <div class="details-body py-2">
                        <input type="hidden" name="file" value="{$dir}"/>
                        <input type="submit" class="btn btn-sm btn-danger" onclick="return confirm('{$confirmMessage}')" name="delete" value="Borrar"/>
                    </div>
                </details>
            </li>
            HTML;
        }

        if ($extType == 'nonEditable' && $extension == 'zip') {
            $buttons = $unZipFiles . $renameHtml . $moveFilesHtml . <<<HTML
            <li class="list-group-item">
                <details>
                    <summary>Actualizar</summary>
                    <div class="details-body py-2">
                        <input type="hidden" name="file" value="{$dir}"/>
                        <input type="submit" class="btn btn-sm btn-primary" name="update" value="Actualizar"/>
                    </div>
                </details>
            </li>
            <li class="list-group-item">
                <details class="danger">
                    <summary>Borrar</summary>
                    <div class="details-body py-2">
                        <input type="hidden" name="file" value="{$dir}"/>
                        <input type="submit" class="btn btn-sm btn-danger" onclick="return confirm('{$confirmMessage}')" name="delete" value="Borrar"/>
                    </div>
                </details>
            </li>
            HTML;
        } else {
            $buttons = $renameHtml . $moveFilesHtml . <<<HTML
            <li class="list-group-item">
                <details>
                    <summary>Actualizar</summary>
                    <div class="details-body py-2">
                        <input type="hidden" name="file" value="{$dir}"/>
                        <input type="submit" class="btn btn-sm btn-primary" name="update" value="Actualizar"/>
                    </div>
                </details>
            </li>
            <li class="list-group-item">
                <details class="danger">
                    <summary>Borrar</summary>
                    <div class="details-body py-2">
                        <input type="hidden" name="file" value="{$dir}"/>
                        <input type="submit" class="btn btn-sm btn-danger" onclick="return confirm('{$confirmMessage}')" name="delete" value="Borrar"/>
                    </div>
                </details>
            </li>
            HTML;
        }
        // Agregamos las funciones de renombrar,editar y borrar
        $this->runEditViewFunctions();

        // Generar el HTML completo para la vista de edición
        $html .= <<<HTML
            <form method="post" style="height:100%">
                <section class="row">
                    <section class="col-md-8">
                        {$content}
                    </section>
                    <aside class="col-md-4">
                        <div class="card border-light shadow">
                            <div class="card-header bg-dark text-light">
                                <h5 class="card-title m-0">Opciones</h5>
                            </div>
                            <div class="card-body p-1 mb-2">
                                <ul class="list-group m-0">
                                    <li class="list-group-item"><strong>Nombre: </strong> {$filename}</li>
                                    <li class="list-group-item"><strong>Extensión: </strong> {$extension}</li>
                                    <li class="list-group-item"><strong>Permisos: </strong> {$fileperms}</li>
                                    <li class="list-group-item"><strong>Tamaño: </strong>{$filesize}</li>
                                    <li class="list-group-item"><strong>Fecha mod. : </strong>{$filedate}</li>
                                    {$buttons}
                                </ul>
                            </div>
                            <div class="card-footer">
                                <div class="btn-group">
                                    {$downloadTpl}
                                    {$openExternalTpl}
                                </div>
                            </div>
                        </div>
                    </aside>
                </section>
            </form>
        HTML;
        // Generar el CSS necesario para la vista de edición
        $css = ".CodeMirror{height: 100%;}.no-preview svg{width:80px;height:80px;fill:var(--bs-light)";
        // Obtener el tipo de archivo
        $mimeType = pathinfo($dir, PATHINFO_EXTENSION);
        // Obtenemos depende del tipo el modo
        $mode = "htmlmixed";
        switch ($mimeType) {
            case 'css':
                $mode = "css";
                break;
            case 'scss':
                $mode = "css";
                break;
            case 'js':
                $mode = "javascript";
                break;
            case 'html':
                $mode = "text/html";
            case 'php':
                $mode = "application/x-httpd-php";
                break;
            case 'json':
                $mode = "javascript";
            case 'md':
                $mode = "markdown";
                break;
        }
        $js = <<<JAVASCRIPT
            document.addEventListener('DOMContentLoaded',() => {
                const EDITOR = CodeMirror.fromTextArea(document.getElementById("editor"), {
                    theme: "material-darker",
                    lineNumbers: true
                });
                EDITOR.setOption('mode','{$mode}');
            },false);
        JAVASCRIPT;
        $cadena = $currentFolder;
        return $this->generateLayout($html, $css, $js, $cadena);
    }

    /**
     * Crea un formulario HTML para subir archivos
     *
     * @return string El código HTML del formulario
     */
    public function uploadFormView(string $dir = ""): string
    {
        // url base
        $url = $this->getOption('Site_url');
        // Remplazamos ROOT por la url actual
        $currentFolder = str_replace(ROOT, '', $dir);
        $currentFolder = str_replace('//', '/', $currentFolder);
        $currentFolder = $currentFolder ? $currentFolder : '/';
        $back = '?get=dir&name=' . base64_encode($dir);
        // Agregamos funciones
        $this->uploadFiles($dir);
        // Creamos el html
        $html = <<<HTML
            <section class="row">
                <div class="col-md-5">
                    <h3> Subir archivos en <span class="badge bg-dark">{$currentFolder}</span></h3>
                    <form method="POST" enctype="multipart/form-data">
                        <div class="mb-3">
                            <input type="file" class="form-control" name="files[]" multiple directory="false" required>
                        </div>
                        <div class="btn-group">
                            <input type="submit" class="btn btn-dark" value="Subir archivo">
                            <a class="btn btn-danger" href="{$back}">Volver</a>
                        </div>
                    </form>
                </div>
            </section>
        HTML;
        // Generamos la plantilla
        return $this->generateLayout($html, '', '', $dir);
    }

    /**
     * Creamos la vista de creacion de directorios y archivos
     *
     * @param string $type
     * @param string $dir
     * @return string
     */
    public function createDirView(string $type = "", string $dir = ""): string
    {
        // url base
        $url = $this->getOption('Site_url');
        // Remplazamos Root por al url actual
        $currentFolder = str_replace(ROOT, '', $dir);
        $currentFolder = str_replace('//', '/', $currentFolder);
        $currentFolder = $currentFolder ? $currentFolder : '/';
        $back = '?get=dir&name=' . base64_encode($dir);
        $name = ($type == 'file') ? 'archivo' : 'carpeta';
        // Agregamos las funciones
        $this->createDirFunctions($type, $dir);
        // Creamos el html
        $html = <<<HTML
        <section class="row">
            <div class="col-md-6">
                <h3> Crear <strong class="text-primary">{$name}</strong> en <span class="badge bg-dark">{$currentFolder}</span></h3>
                <form method="POST">
                    <div class="mb-3">
                        <input type="text" class="form-control" name="name" placeholder="Nombre {$name}" required>
                    </div>
                    <div class="btn-group">
                        <input type="submit" class="btn btn-dark" name="create" value="Crear">
                        <a class="btn btn-danger" href="{$back}">Volver</a>
                    </div>
                </form>
            </div>
        </section>
        HTML;
        // Generamos la plantilla
        return $this->generateLayout($html, '', '', $dir);
    }
    /**
     * Creamos la vista de borrado de directorios
     *
     * @param string $dir
     * @return string
     */
    public function removeDirView(string $dir = ""): string
    {
        // url base
        $url = $this->getOption('Site_url');
        // Obtener la ruta de la carpeta actual
        $currentFolder = str_replace(ROOT, '', $dir);
        $currentFolder = str_replace('//', '/', $currentFolder);
        $currentFolder = $currentFolder ? $currentFolder : '/';
        // Agregamos las funciones
        $this->removeDirFunctions($dir);
        // Creamos el html
        $html = <<<HTML
        <section class="row">
            <div class="col-md-5">
                <h3> Borrar carpeta</h3>
                <p> Se va a proceder al borrado de la carpeta <span class="badge bg-dark">{$currentFolder}</span> </p>
                <form method="POST">
                    <input type="hidden" name="dir" value="{$dir}">
                    <div class="btn-group">
                        <input type="submit" class="btn btn-dark" name="delete" value="Borrar">
                        <a class="btn btn-danger" href="{$url}" title="Volver al inicio">Volver</a>
                    </div>
                </form>
            </div>
        </section>
        HTML;
        // Generamos la plantilla
        return $this->generateLayout($html, '', '', $dir);
    }

    /**
     * Creamos la vista de el login
     *
     * @param string $dir
     * @return string
     */
    public function loginView(string $dir = ""): string
    {
        // url base
        $url = $this->getOption('Site_url');
        // title
        $title = $this->getOption('title');
        $logo = $this->getOption('logo');
        // Captcha
        $captcha = $this->tokenCaptcha(6, '123456790');
        // Token
        $token = $this->tokenGenerate();
        // client hash
        $client_hash = $this->client_hash;
        // Funciones del login
        $this->loginAuthFunctions($token);
        // html
        $html = <<<HTML
            <div class="row">
                <div class="col-12 col-sm-6 col-md-4 col-xl-4 col-xxl-4 m-auto">
                    <div class="card shadow">
                        <div class="card-header bg-dark text-light">
                            <img class="rounded-pill me-2" src="{$logo}" alt="logo">
                            <span>{$title}</span>
                        </div>
                        <form method="post">
                            <input type="hidden" name="_captcha" value="{$captcha}"/>
                            <input type="hidden" name="_hash" value="{$client_hash}"/>
                            <div class="card-body">
                                <div class="mb-3">
                                    <label for="password" class="form-label">Contraseña</label>
                                    <input type="password" class="form-control" name="password" placeholder="**********" autocomplete="current-password" required>
                                </div>
                                <div class="mb-3">
                                    <label for="catpcha" class="form-label">Escriba el numero {$captcha} </label>
                                    <input type="number" class="form-control" name="captcha" title="captcha" required>
                                </div>
                            </div>
                            <div class="card-footer">
                                <input type="submit" class="btn btn-sm btn-primary" name="loginAuth" value="Entrar"/>
                                <a href="/" class="btn btn-sm btn-danger">Salir</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        HTML;
        // css
        $css = '';
        // generamos el layout
        return $this->generateLayout($html, $css, '', $dir);
    }

    /**
     * Creamos la vista de generar password
     *
     * @return void
     */
    public function generatePasswordView(): void
    {
        // Obtenemos la URL del sitio utilizando la opción 'Site_url'
        $url = $this->getOption('Site_url');

        // Generamos la salida necesaria para la vista
        $output = $this->generatePasswordFunctions();

        // Creamos un bloque de HTML utilizando la sintaxis HEREDOC
        $html = <<<HTML
            <section class="row">
                <div class="col-md-5">
                    <form method="post">
                        <div class="mb-3">
                            <label class="form-label">Generar contraseña</label>
                            <input class="form-control" name="pass" placeholder="demo123" required/>
                        </div>
                        <div class="mb-3 btn-group">
                            <input type="submit" class="btn btn-dark" name="generate" value="Generar"/>
                            <a class="btn btn-danger" href="{$url}">Volver</a>
                        </div>
                    </form>
                    <div class="output">
                        <pre class="bg-dark text-light p-2 shadow rounded-1" style="user-select:all;">{$output}</pre>
                    </div>
                </div>
            </section>
        HTML;

        // Imprimimos el bloque de HTML en la pantalla utilizando la función generateLayout
        echo $this->generateLayout($html, '', '', ROOT);
    }

}

/**
 * Trait FormsFunctions
 * Este trait proporciona funciones para los formularios de los views.
 *
 * loginAuthFunctions: Funcion de login.
 * removeDirFunctions: Borrar carpeta.
 * createDirFunctions: Crea un archivo o una carpeta en un directorio específico.
 * uploadFiles: Subir archivos.
 * runEditViewFunctions: Funciones para la vista editar.
 *
 * @package MediaManager
 * @category Trait
 */
trait FormsFunctions
{

    /**
     * Funcion para generar password
     *
     * @return string
     */
    public function generatePasswordFunctions(): string
    {
        // Inicializamos la variable de salida
        $output = '';

        // Verificamos si el botón 'generate' fue presionado en el formulario
        if (array_key_exists('generate', $_POST)) {
            // Obtenemos la contraseña ingresada por el usuario en el campo 'pass'
            $output = $this->getPost('pass');

            // Generamos el hash de la contraseña utilizando el algoritmo PASSWORD_DEFAULT
            $output = password_hash($output, PASSWORD_DEFAULT);
        }

        // Devolvemos la contraseña generada (o una cadena vacía si el formulario no ha sido enviado)
        return ($output) ? $output : 'Aquí se verá la contraseña 🚀';
    }

    /**
     * Funcion de login
     *
     * @param string $token Token generado en el view
     * @return void
     */
    public function loginAuthFunctions(string $token = "")
    {
        // comprobamos la cookie
        if (array_key_exists('usuario_bloqueado', $_COOKIE)) {
            die($this->toManyAttempts());
            exit();
        }
        // botton sign in
        if (array_key_exists('loginAuth', $_POST)) {
            // comprobamos token
            if ($this->tokenCheck($token) && $this->client_hash == $this->getPost('_hash', false)) {
                // comprobamos captcha
                if ($this->getPost('captcha') == $this->getPost('_captcha', false)) {
                    return $this->login();
                } else {
                    // Informacion error
                    $this->msgSet("Error 😫", "El código que has ingresado es incorrecto");
                    $this->redirect($this->getOption('Site_url'));
                }
            } else {
                die('CRSF detectado');
            }
        }
    }

    /**
     * Borrar carpeta
     *
     * @param string $dir directorio a borrar
     * @return void
     */
    public function removeDirFunctions(string $dir = ""): void
    {
        // Comprobamos create
        if (array_key_exists('delete', $_POST)) {
            try {
                $success = $this->removeDir($dir);
                // Mensaje y redirecionamos
                $this->msgSet('Bien 😀', "Se han eliminado {$success} archivos y directorios correctamente.");
                $this->redirect($this->getOption('Site_url'));
            } catch (Exception $e) {
                // Mensaje y redirecionamos
                $this->msgSet('Oh 🙄', "Error al eliminar el directorio: " . $e->getMessage());
                $this->redirect($this->getOption('Site_url') . '?delete=dir&where=' . base64_encode($dir));
            }
        }
    }

    /**
     * Crea un archivo o una carpeta en un directorio específico.
     *
     * @param string $type El tipo de elemento a crear (opciones: "file" o "dir").
     * @param string $dir La ruta del directorio donde se creará el elemento.
     *
     * @return void No devuelve ningún valor.
     */
    public function createDirFunctions(string $type = "", string $dir = "")
    {
        // Comprobamos create
        if (array_key_exists('create', $_POST)) {
            if ($type == 'file') {
                $name = $this->getPost('name');
                if ($this->createFile($dir, $name)) {
                    // Mensaje y redirecionamos
                    $this->msgSet('Bien 😀', "El archivo {$name} se ha creado correctamente");
                    $this->redirect($this->getOption('Site_url') . '?get=file&name=' . base64_encode($dir . '/' . $name));
                } else {
                    // Mensaje y redirecionamos
                    $this->msgSet('Oh 🙄', "El archivo {$name} no tiene extension o no es un archivo editable");
                    $this->redirect($this->getOption('Site_url') . '?create=' . $type . '&where=' . base64_encode($dir));
                }
            } elseif ($type == 'dir') {
                $name = $this->getPost('name');
                $name = $this->cleanName($name);
                if ($this->createDir($dir, $name)) {
                    // Mensaje y redirecionamos
                    $this->msgSet('Bien 😀', "La carpeta {$name} se ha creado correctamente");
                    $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode($dir . '/' . $name));
                } else {
                    // Mensaje y redirecionamos
                    $this->msgSet('Oh 🙄', "La carpeta {$name} ya existe");
                    $this->redirect($this->getOption('Site_url') . '?create=' . $type . '&where=' . base64_encode($dir));
                }
            }
        }
    }

    /**
     * Subir archivos
     *
     * @param string $dir directorio para subir archivos
     * @return void
     */
    public function uploadFiles(string $dir = "")
    {
        // Comprobamos si se ha enviado un archivo
        if (isset($_FILES['files'])) {
            $file = $_FILES['files'];
            $totalFiles = count($file['name']); // Obtenemos el número total de archivos a subir
            $uploadedFiles = 0; // Inicializamos el contador de archivos subidos a cero
            // Iteramos sobre cada archivo
            for ($i = 0; $i < $totalFiles; $i++) {
                $filename = $file['name'][$i]; // Obtenemos el nombre del archivo
                $tmpname = $file['tmp_name'][$i]; // Obtenemos la ruta temporal donde se ha guardado el archivo
                // Obtenemos la información del archivo
                $info = pathinfo($filename, PATHINFO_EXTENSION);
                // Verificamos que la extensión del archivo sea válida (es decir, es una imagen o un archivo editable)
                list("isValid" => $isValid, "extType" => $extType) = $this->checkExtension($info);
                if ($isValid) {
                    // Guardamos el archivo
                    $upload_dir = $dir . '/';
                    $upload_dir = str_replace('//', '/', $upload_dir);
                    // Carpeta de destino
                    $destination = $upload_dir . basename($filename);
                    // Movemos el archivo al directorio y contamos
                    if (move_uploaded_file($tmpname, $destination)) {
                        // Incrementamos el contador de archivos subidos
                        $uploadedFiles++;
                    }
                } else {
                    $this->msgSet('Oh 🙄', "Hubo un problema al subir el archivo {$filename}");
                }
            }
            // Redirigimos a la página de destino con un mensaje de éxito o fracaso
            if ($uploadedFiles == $totalFiles) {
                $this->msgSet('Bien 😁', 'La subida de archivos ha tenido exito :)');
                $this->redirect($url . '?get=dir&name=' . base64_encode($dir));
            } else {
                $this->msgSet('Oh 🙄', 'Hubo un problema al subir el archivo');
                $this->redirect($url . '?get=dir&name=' . base64_encode($dir));
            }
        }
    }

    /**
     * Funciones para la vista editar
     *
     * @return void
     */
    public function runEditViewFunctions()
    {
        // Llamamos a las funciones rename
        if (array_key_exists('rename', $_POST)) {
            $oldRenameDir = $this->getPost('oldRenameDir');
            $newRenameFile = $this->getPost('newRenameFile');
            $oldRenameFile = $this->getPost('oldRenameFile');
            $extension = pathinfo($oldRenameDir, PATHINFO_EXTENSION);
            // Sanitizamos un poco
            $name = strtolower($newRenameFile); // Convierte el texto a minúsculas
            $name = str_replace(" ", "-", $name); // Reemplaza los espacios por guiones
            $name = preg_replace("/[^a-z0-9]+/", "-", $name); // Elimina caracteres especiales y acentos
            $name = trim($name, "-"); // Elimina guiones al principio y al final
            $name = preg_replace("/-{2,}/", "-", $name); // Elimina guiones duplicados
            // La ruta y el nuevo nombre
            $newfilename = dirname($oldRenameDir) . '/' . $name . '.' . $extension;
            // Intenta renombrar el archivo
            if (rename($oldRenameDir, $newfilename)) {
                // Si el archivo ha sido renombrado, comprueba que existe con el nuevo nombre
                if (file_exists($newfilename)) {
                    // Si el archivo existe con el nuevo nombre, continúa con las acciones que desees
                    $this->msgSet('Bien 😀', 'El archivo se ha renombrado exitosamente.');
                    $url = $this->getOption('Site_url') . '/?get=file&name=' . base64_encode($newfilename);
                    $this->redirect($url);
                } else {
                    // Si hay error enviamos mensaje y refrescamos
                    $this->msgSet('Oh 🙄', 'Ha ocurrido un error al renombrar el archivo.');
                    $url = $this->getOption('Site_url') . '/?get=file&name=' . base64_encode($file);
                    $this->redirect($url);
                }
            } else {
                $this->msgSet('Oh 🙄', 'Ha ocurrido un error al renombrar el archivo.');
                $url = $this->getOption('Site_url') . '/?get=file&name=' . base64_encode($file);
                $this->redirect($url);
            }
        }
        // Llamamos a las funciones delete
        if (array_key_exists('delete', $_POST)) {
            $file = $this->getPost('file');
            // Intenta borrar el archivo
            if ($this->removeFile($file)) {
                $this->msgSet('Bien 😀', 'El archivo se ha borrado exitosamente.');
                $url = $this->getOption('Site_url') . '/?get=dir&name=' . base64_encode(dirname($file));
                $this->redirect($url);
            } else {
                $this->msgSet('Oh 🙄', 'El no hemos podigo borrar el archivo.');
                $url = $this->getOption('Site_url') . '/?get=file&name=' . base64_encode($file);
                $this->redirect($url);
            }
        }
        // Llamamos a las funciones update
        if (array_key_exists('update', $_POST)) {
            $file = $this->getPost('file');
            $data = $this->getPost('editor', false);
            // Si se guarda bien enviamos mensaje y redirigimos al mismo sitio
            if ($this->saveContent($file, $data)) {
                $this->msgSet('Bien 😀', 'El archivo se ha actualizado exitosamente.');
                $url = $this->getOption('Site_url') . '/?get=file&name=' . base64_encode($file);
                $this->redirect($url);
            } else {
                $url = $this->getOption('Site_url') . '/?get=file&name=' . base64_encode($file);
                $this->msgSet('Oh 🙄', 'El archivo no se ha podido actualizar');
            }
        }
        // Llamamos a las funciones mover
        if (array_key_exists('move', $_POST)) {
            $old = $this->getPost('old');
            $filename = $this->getPost('filename');
            $new = $this->getPost('new');
            $extension = pathinfo($filename, PATHINFO_EXTENSION);
            // Sanitizamos un poco
            $name = strtolower($new); // Convierte el texto a minúsculas
            $name = str_replace(" ", "-", $name); // Reemplaza los espacios por guiones
            $name = preg_replace("/[^a-z0-9]+/", "-", $name); // Elimina caracteres especiales y acentos
            $name = trim($name, "-"); // Elimina guiones al principio y al final
            $name = preg_replace("/-{2,}/", "-", $name); // Elimina guiones duplicados
            // Llamamos a la funcion moveFiles
            $this->moveFiles($filename, $old, $new);
        }
        // Llamamos a la funcion descomprimir
        if (array_key_exists('unzip', $_POST)) {
            // Verifica si el botón 'unzip' ha sido presionado en el formulario POST
            $filename = $this->getPost('file'); // Obtiene el nombre del archivo a descomprimir desde el formulario POST
            $newFileDir = ROOT . '/' . $this->getPost('newDirFile'); // Obtiene la ubicación donde se creará la carpeta para almacenar el contenido del archivo descomprimido
            $outputDir = pathinfo($filename, PATHINFO_FILENAME); // Obtiene el nombre del archivo sin la extensión
            $outputPath = $newFileDir . '/' . $this->cleanName($outputDir); // Establece la ruta donde se almacenará el contenido del archivo descomprimido
            if (!is_dir($outputPath)) {
                // Verifica si la carpeta de destino no existe
                mkdir($outputPath, 0777, true); // Crea la carpeta de destino recursivamente con permisos de lectura, escritura y ejecución para todos los usuarios
                $this->unzip($filename, $outputPath); // Descomprime el archivo en la carpeta de destino
            }
        }
    }
}

/**
 * Clase MediaManager
 *
 * Esta clase proporciona una interfaz para gestionar archivos y carpetas.
 * Contiene métodos para obtener opciones de configuración, obtener archivos y carpetas, mostrar vistas HTML y manejar errores.
 * Utiliza las traits Utils, Info y HtmlViews para proporcionar funcionalidades adicionales.
 *
 * @author Moncho Varela
 * @version 0.01
 */
class MediaManager
{

    use Session;
    use Auth;
    use Token;
    use Icons;
    use Utils;
    use FilesystemInfo;
    use HtmlView;
    use FormsFunctions;
    use Msg;

    // config vars
    public static $defaultConfig = [
        'Site_url' => 'http://localhost/root.php',
        'password' => '$2y$10$n5xO5I4XTPt.WZaSGI0x5OEZQoDoBU2dDYrAq8yLXBsb512KfnP2G', // default password demo123;
        'title' => 'App name',
        'logo' => '',
        'exclude' => ['root', '.gitignore', '.git', 'node_modules', '.htaccess', 'temp', '_temp_files'],
        'imageSupport' => ["ico", "jpg", "jpeg", "png", "gif", "svg", "bmp", "webp"],
        'videoSupport' => ["mp4", "webm", "ogg", "mov", "avi", "wmv", "flv", "m4v", "mkv", "mpeg", "mpg", "3gp"],
        'audioSupport' => ["wav", "mp3", "ogg", "m4a"],
        'editableFilesSupport' => ['env', 'less', 'scss', 'jsx', 'ts', 'tsx', 'json', 'sql', 'manifest', 'txt', 'md', 'html', 'htm', 'xml', 'css', 'js', 'php', 'c', 'cpp', 'h', 'hpp', 'py', 'rb', 'java', 'sh', 'pl'],
        'nonEditableFilesSupport' => ["ttf", "otf", "woff", "woff2", "docx", "xlsx", "pptx", "accdb", "pub", "vsd", "doc", "xls", "ppt", "mdb", 'mo', 'po', 'db', 'pdf', 'zip'],
    ];

    /**
     * Construct
     *
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->sessionStart();
        // Fusiona el array de configuraciones por defecto con el array de configuraciones que se pasa como argumento en el constructor
        $this->config = array_merge(self::$defaultConfig, $config);
        // Hash de login y cliente
        foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'] as $key) {
            $ip = isset($_SERVER[$key]) && !empty($_SERVER[$key]) ? explode(',', $_SERVER[$key])[0] : '';
            if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                break;
            }

        }
        // datos de seguridad
        $this->ip = $ip;
        $this->client_hash = md5($ip . (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '') . __FILE__ . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ''));
        $this->login_hash = md5($this->getOption('password') . $this->client_hash);
    }

    /**
     * Retorna el valor de una opción específica del array de configuración de la clase.
     *
     * @param string $key La clave de la opción que se desea obtener.
     * @return mixed|null El valor de la opción correspondiente a la clave especificada o null si la clave no existe.
     */
    public function getOption($key)
    {
        // Verifica si la clave $key está presente en el array de configuración $config
        if (isset($this->config[$key])) {
            // Si la clave existe, retorna el valor correspondiente
            return $this->config[$key];
        } else {
            // Si la clave no existe, retorna null
            return null;
        }
    }

    /**
     * Punto de entrada de la aplicación
     */
    public function init()
    {
        // Obtenemos los archivos
        if (array_key_exists('get', $_GET)) {
            // Comprobamos si es archivo
            if ($this->get('get') == 'file') {
                // Obtenemos el nombre del archivo
                if (array_key_exists('name', $_GET)) {
                    $filepath = base64_decode($this->get('name'));
                    // Mostramos la vista de edición del archivo
                    echo $this->editView($filepath);
                } else {
                    // Error, el nombre del archivo no existe
                    $this->error('Error, el nombre del archivo no existe');
                }
                // Comprobamos si es carpeta
            } elseif ($this->get('get') == 'dir') {
                // Obtenemos el nombre de la carpeta
                if (array_key_exists('name', $_GET)) {
                    $filepath = base64_decode($this->get('name'));
                    // Mostramos la vista por defecto de la carpeta
                    echo $this->defaultView($filepath);
                } else {
                    // Error, el nombre de la carpeta no existe
                    $this->error('Error, el nombre de la carpeta no existe');
                }
            } elseif ($this->get('get') == 'upload') {
                // Obtenemos el nombre de la carpeta
                if (array_key_exists('name', $_GET)) {
                    $filepath = base64_decode($this->get('name'));
                    // Si el usuario quiere subir un archivo, mostramos el formulario para subir archivos
                    echo $this->uploadFormView($filepath);
                } else {
                    // Error, el nombre de la carpeta no existe
                    $this->error('Error, el nombre de la carpeta no existe');
                }
            } else {
                // Error, el tipo de archivo no existe
                $this->msgSet('Error 😫', 'El tipo de archivo no existe');
            }
        } elseif (array_key_exists('create', $_GET)) {
            // Obtenemos el nombre de la carpeta
            if (array_key_exists('where', $_GET)) {
                $filepath = base64_decode($this->get('where'));
                $filetype = $this->get('create');
                // Si el usuario quiere crear un archivo o una carpeta mostramos la vista de crear
                echo $this->createDirView($filetype, $filepath);
            } else {
                // Error, el nombre de la carpeta no existe
                $this->error('Error, el nombre de la carpeta no existe');
            }
        } elseif (array_key_exists('delete', $_GET)) {
            // Obtenemos el nombre de la carpeta
            if (array_key_exists('where', $_GET)) {
                $filepath = base64_decode($this->get('where'));
                // Si el usuario quiere borrar la carpeta mostramos la vista de borrar
                echo $this->removeDirView($filepath);
            } else {
                // Error, el nombre de la carpeta no existe
                $this->error('Error, el nombre de la carpeta no existe');
            }
        } elseif (array_key_exists('generar', $_GET)) {
            // Obtenemos el nombre de la carpeta
            if ($this->get('generar') == 'password') {
                $this->generatePasswordView();
            } else {
                // Error, el nombre de la carpeta no existe
                $this->error('Error, el nombre de la carpeta no existe');
            }
        } else {
            // Mostramos la vista por defecto del directorio raíz
            echo $this->defaultView(ROOT);
        }

        // salir
        if (array_key_exists('logout', $_GET)) {
            $this->logout();
            $this->redirect($this->getOption('Site_url'));
        }
    }

    /**
     * Api simple
     *
     * @return void
     */
    public function api()
    {
        if (array_key_exists('api', $_GET)) {
            // Imprime en formato Json
            @header('content-type: application/json');
            $data = [];
            // Obtenemos los directorios
            if ($this->get('api') == 'd') {
                // Comprobamos si existe name
                if (array_key_exists('name', $_GET)) {
                    // Decodificamos el enlace
                    $filename = base64_decode($this->get('name'));
                    // Generar el contenido según el tipo de archivo
                    $data['status'] = true;
                    $data['data'] = $this->getDirInfo($filename);
                } else {
                    $data['status'] = true;
                    $data['data'] = $this->getDirInfo(ROOT);
                }
            } elseif ($this->get('api') == 'f') {
                // Comprobamos si existe name
                if (array_key_exists('name', $_GET)) {
                    // Decodificamos el enlace
                    $filename = base64_decode($this->get('name'));
                    // Generar el contenido según el tipo de archivo
                    $data['status'] = true;
                    $data['getpwuid'] = function_exists('posix_getpwuid') ? posix_getpwuid(fileowner($filename)) : '';
                    $data['getgrgid'] = function_exists('posix_getgrgid') ? posix_getgrgid(filegroup($filename)) : '';
                    $data['data'] = $this->getFileInfo($filename);
                }
            }
            // Imprimimos en Json.
            $output = json_encode($data, JSON_PRETTY_PRINT, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
            print($output);
            exit();
        }
    }

    /**
     * Iniciamos la aplicación
     *
     * @return void
     */
    public function run()
    {
        if ($this->isLogin()) {
            $this->api();
            return $this->init();
        } else {
            echo $this->loginView();
        }
    }
}

$MediaManager = new MediaManager([
    'Site_url' => 'http://localhost/root.php',
    'password' => '$2y$10$n5xO5I4XTPt.WZaSGI0x5OEZQoDoBU2dDYrAq8yLXBsb512KfnP2G',// demo123
    'title' => 'Root App',
    'logo' => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAjpJREFUWEftlcsrRFEcx3/TlCahSFkgyqORKQszyiOFjTw2SikLOxsrZSNqUiYbZeUPsFBKzUZkg5RHcSzUlMmjCAslCjHJNPqd8buOa849584jG7/Vveeec76f8/3+TtdRGxyOwR+W4x9Ax4HxkZOkQpqZr1Gu04qAAAYu1pUb4oSlik4+Ly0AJD54uQrRqNPYXEaCkE5nFBbLu7UglA6YTz9d1AD++32ArFyYyvNwEf9TCOD9GaYKG2Hy7oCP6bpgG0Arg0wB0KlUEBhD2h1A0fOXB5U2/16ZU2DMUzWiVgQkjNl31eUZm68dP/Fn8xj2AoGkDYA3no0iiOWFZstVSgf6h3ZhpdoFbG8LvE1tPzbDMaxE4zjWexqBlABC3bO/BBhj8TGv9ycMY4B/NZ8wToCe1TGpC5YOEIB4ykPGYLTVATuv9dwV+taSfQRz2zHw+eJg9A2fUwOIPAK48qVWyyLgC77WJg2Ae4gu2OhBY6qVOE5SNmEiCHfp91UUocLX8WtJpRJPCkAmTqIiRMYAuAjmK5YrHxAu4wCWfZCVy/+KaY9A1owUhzl71dUTD6HVhLQg1OPnj+6SYgjf3AK8ffD3WLYTaopLDPt1sqc9bQFwJzomwF1VljCJ8NkVeDYCtm5rUgDcBRMEinPrMwngChwB2wxantDb3geRiXptF7QdQHEsHQCcpwuhBUDidgB0IZQAorjoq9kJtD5RqZywBJCJkxBByMRpnhWEFEAlLsahArCK488BPgGWqTzwXrlG8gAAAABJRU5ErkJgggAA',
    'exclude' => ['root.php', '.gitignore', '.git', 'node_modules', '.htaccess', 'temp', '_temp_files'],
]);

// Iniciamos la aplicación
$MediaManager->run();
