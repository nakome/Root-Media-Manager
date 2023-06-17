<?php

declare (strict_types = 1);

/**
 * +-------------------------------------------------------------------+
 * |                    GESTOR DE ARCHIVOS   (v1.1)                    |
 * |                                                                   |
 * | Copyright Moncho Varela            www.monchovarela.es            |
 * | Created: May. 7, 2023              Last modified: junio. 14, 2023 |
 * +-------------------------------------------------------------------+
 * | This program may be used and hosted free of charge by anyone for  |
 * | personal purpose as long as this copyright notice remains intact. |
 * |                                                                   |
 * | Obtain permission before selling the code for this program or     |
 * | hosting this software on a commercial website or redistributing   |
 * | this software over the Internet or in any other medium. In all    |
 * | cases copyright must remain intact.                               |
 * +-------------------------------------------------------------------+
 */

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
header("Content-Security-Policy: img-src  'self' data:; script-src 'self' https://imgbb.com https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'");
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
    @ini_set('error_reporting', (string) E_ALL);
    @ini_set('display_errors', (string) 1);
} else {
    @ini_set('error_reporting', (string) E_ALL);
    @ini_set('display_errors', (string) 0);
}

// Opciones básicas
$options = [
    'Site_url' => 'http://localhost:8000',
    'password' => '$2y$10$ErfmRft0n5cFAA.r3RLIgeRqtIo6ycU85JbtyqWFOMZ.ZVsFHjx2a', // insame69&;
    'title' => 'Gestor de archivos',
    'emojiFavicon' => '🐱‍👤',
    'logo' => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAjpJREFUWEftlcsrRFEcx3/TlCahSFkgyqORKQszyiOFjTw2SikLOxsrZSNqUiYbZeUPsFBKzUZkg5RHcSzUlMmjCAslCjHJNPqd8buOa849584jG7/Vveeec76f8/3+TtdRGxyOwR+W4x9Ax4HxkZOkQpqZr1Gu04qAAAYu1pUb4oSlik4+Ly0AJD54uQrRqNPYXEaCkE5nFBbLu7UglA6YTz9d1AD++32ArFyYyvNwEf9TCOD9GaYKG2Hy7oCP6bpgG0Arg0wB0KlUEBhD2h1A0fOXB5U2/16ZU2DMUzWiVgQkjNl31eUZm68dP/Fn8xj2AoGkDYA3no0iiOWFZstVSgf6h3ZhpdoFbG8LvE1tPzbDMaxE4zjWexqBlABC3bO/BBhj8TGv9ycMY4B/NZ8wToCe1TGpC5YOEIB4ykPGYLTVATuv9dwV+taSfQRz2zHw+eJg9A2fUwOIPAK48qVWyyLgC77WJg2Ae4gu2OhBY6qVOE5SNmEiCHfp91UUocLX8WtJpRJPCkAmTqIiRMYAuAjmK5YrHxAu4wCWfZCVy/+KaY9A1owUhzl71dUTD6HVhLQg1OPnj+6SYgjf3AK8ffD3WLYTaopLDPt1sqc9bQFwJzomwF1VljCJ8NkVeDYCtm5rUgDcBRMEinPrMwngChwB2wxantDb3geRiXptF7QdQHEsHQCcpwuhBUDidgB0IZQAorjoq9kJtD5RqZywBJCJkxBByMRpnhWEFEAlLsahArCK488BPgGWqTzwXrlG8gAAAABJRU5ErkJgggAA',
    'exclude' => ['.gitignore', '.git', 'node_modules', '.htaccess', 'temp', '_temp_files'],
    'imageSupport' => ["ico", "jpg", "JPG", "JPEG", "jpeg", "png", "gif", "svg", "bmp", "webp"],
    'videoSupport' => ["mp4", "webm", "ogg", "mpeg", "mpg", "3gp"],
    'audioSupport' => ["wav", "mp3", "ogg", "m4a"],
    'editableFilesSupport' => ['env', 'less', 'scss', 'jsx', 'ts', 'tsx', 'json', 'sql', 'manifest', 'txt', 'md', 'html', 'htm', 'xml', 'css', 'js', 'php', 'c', 'cpp', 'h', 'hpp', 'py', 'rb', 'java', 'sh', 'pl'],
    'nonEditableFilesSupport' => ["ttf", "otf", "woff", "woff2", "docx", "xlsx", "pptx", "accdb", "pub", "vsd", "doc", "xls", "ppt", "mdb", 'mo', 'po', 'db', 'pdf', 'zip'],
];

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
 *
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

trait ExifTrait
{
    /**
     * Codifica si es requerido
     */
    public function safeImageIPTC($val)
    {
        // Limita la cadena a 1000 caracteres
        $val = @substr($val, 0, 1000);
        // Verifica si la cadena está en formato UTF-8, de lo contrario la codifica
        return @mb_detect_encoding($val, 'UTF-8', true) ? $val : @utf8_encode($val);
    }

    /**
     * IPTC image
     */
    public function imageIPTC($image_info)
    {
        // Verifica si existe información de IPTC en la imagen y si la función iptcparse está disponible
        if (!$image_info || !isset($image_info['APP13']) || !function_exists('iptcparse')) {
            return;
        }

        // Parsea los datos IPTC de la imagen
        $app13 = @iptcparse($image_info['APP13']);
        if (empty($app13)) {
            return;
        }

        $iptc = array();

        // Recorre los campos de título, encabezado, descripción, creador, crédito, derechos de autor, palabras clave, ciudad, sub-ubicación y provincia/estado
        foreach (['title' => '005', 'headline' => '105', 'description' => '120', 'creator' => '080', 'credit' => '110', 'copyright' => '116', 'keywords' => '025', 'city' => '090', 'sub-location' => '092', 'province-state' => '095'] as $name => $code) {
            if (isset($app13['2#' . $code][0]) && !empty($app13['2#' . $code][0])) {
                // Si el campo es palabras clave, se asigna directamente el valor, de lo contrario se codifica si es necesario
                $iptc[$name] = $name === 'keywords' ? $app13['2#' . $code] : $this->safeImageIPTC($app13['2#' . $code][0]);
            }
        }

        // Retorna los datos IPTC
        return $iptc;
    }

    /**
     * Timestamp image
     */
    public function imageExifTimestamp($str)
    {
        // Convierte una cadena de fecha y hora en un timestamp UTC
        try {
            return (new DateTime($str, new DateTimeZone('UTC')))->getTimestamp();
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Exif image
     */
    public function imageExif($path)
    {
        // Verifica si la función exif_read_data está disponible
        if (!function_exists('exif_read_data')) {
            return;
        }

        // Lee los datos Exif de la imagen
        $exif_data = @exif_read_data($path, 'ANY_TAG', false);
        if (empty($exif_data) || !is_array($exif_data)) {
            return;
        }

        $exif = array();
        foreach (array('DateTime', 'DateTimeOriginal', 'ExposureTime', 'FNumber', 'FocalLength', 'Make', 'Model', 'Orientation', 'ISOSpeedRatings', 'Software') as $name) {
            $val = isset($exif_data[$name]) ? $exif_data[$name] : false;
            if ($val) {
                // Si el campo es una fecha y hora, se convierte en un timestamp UTC; de lo contrario, se guarda tal como está
                $exif[$name] = strpos($name, 'DateTime') === 0 ? $this->imageExifTimestamp($val) : (is_string($val) ? trim($val) : $val);
            }
        }

        // ApertureFNumber (f_stop) calculado
        if (isset($exif_data['COMPUTED']['ApertureFNumber'])) {
            $exif['ApertureFNumber'] = $exif_data['COMPUTED']['ApertureFNumber'];
        }

        // GPS
        $exif['gps'] = $this->imageLocation($exif_data);

        // Retorna los datos Exif filtrados
        return array_filter($exif);
    }

    /**
     * Localización de la imagen
     */
    public function imageLocation($exif)
    {
        $arr = array();
        foreach (array('GPSLatitude', 'GPSLongitude') as $key) {
            if (!isset($exif[$key]) || !isset($exif[$key . 'Ref'])) {
                return false;
            }

            $coordinate = $exif[$key];
            if (is_string($coordinate)) {
                $coordinate = array_map('trim', explode(',', $coordinate));
            }

            for ($i = 0; $i < 3; $i++) {
                $part = explode('/', $coordinate[$i]);
                if (count($part) == 1) {
                    $coordinate[$i] = $part[0];
                } else if (count($part) == 2) {
                    if ($part[1] == 0) {
                        return false;
                    }
                    // No puede ser 0 / GPS no válido
                    $coordinate[$i] = floatval($part[0]) / floatval($part[1]);
                } else {
                    $coordinate[$i] = 0;
                }
            }
            list($degrees, $minutes, $seconds) = $coordinate;
            $sign = ($exif[$key . 'Ref'] == 'W' || $exif[$key . 'Ref'] == 'S') ? -1 : 1;
            $arr[] = $sign * ($degrees + $minutes / 60 + $seconds / 3600);
        }
        return empty($arr) ? false : $arr;
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
    public function tokenGenerate($length = 32): string
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
 * - toManyAttempts: Esta función devuelve una página HTML indicando que se han realizado demasiados intentos de acceso y
 * se ha bloqueado temporalmente el acceso. Esta página se mostrará al usuario en caso de que haya superado el número máximo
 * de intentos fallidos de inicio de sesión.
 * - isLogin: Esta función verifica si el usuario ha iniciado sesión o no. Devuelve true si se han cumplido las condiciones
 * necesarias para considerar que el usuario ha iniciado sesión, y false en caso contrario.
 * - login: Esta función se encarga de realizar el proceso de inicio de sesión del usuario. En primer lugar, comprueba que
 * la contraseña no esté vacía. Si hay 3 o más intentos fallidos de inicio de sesión, se bloquea el acceso del usuario temporalmente.
 * Si existe una cookie de bloqueo de usuario, se muestra una página HTML indicando que el acceso está bloqueado.
 * Si la contraseña es correcta, se insertan las variables de sesión correspondientes y se redirige al usuario a la página principal.
 * Si la contraseña es incorrecta, se incrementa el contador de intentos fallidos y se muestra un mensaje de error al usuario,
 * indicando cuántos intentos le quedan antes de ser bloqueado.
 * - logout: Esta función se encarga de cerrar la sesión del usuario, eliminando todas las variables de sesión y redirigiéndolo al
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
        return '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Acceso bloqueado</title><link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>' . $this->getOption('emojiFavicon') . '</text></svg>"><style rel="stylesheet">*{box-sizing:border-box}body,html{position:relative;height:100%}body{margin:0;padding:0;background:#eee}main{display:flex;justify-content:center;align-items:center;height:100%}section{margin:5px;max-width:30rem;padding:10px 20px;width:100%;border-radius:4px;background:#fff;border:1px solid #ddd}section h1{font-size:28px;line-height:1.5;margin:0;margin-bottom:10px;color:#333}section p{margin:0;margin-bottom:10px;font-size:16px;line-height:1.5;color:#777}</style></head><body><main><section><h1>Ups, demasiados intentos de acceso</h1><p>Tiene que esperar <span id="num">5</span> segundos para volver a intentarlo. </p></section><script rel="javascript">let id=document.getElementById("num"),count=5,i=setInterval(()=>{count-=1,id.textContent=count,0===count&&location.reload(!0)},1e3);</script></main></body></html>';
    }

    /**
     * Verifica si el usuario ha iniciado sesión.
     *
     * @return bool
     */
    public function isLogin(): bool
    {
        // Verificar si existen las claves necesarias en la sesión y si el hash de inicio de sesión coincide
        if ($this->sessionGet('_ip') &&
            $this->sessionGet('_time') &&
            $this->__login_hash == $this->sessionGet('_login_hash')) {
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
            setcookie('usuario_bloqueado', (string) true, time() + 5, "/", "", true, true);
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
            exit(0);
        } else {

            $password = trim($this->getPost('password', true));
            // Comprobar si la contraseña es correcta
            if ($hasher->verify($password, $this->getOption('password'))) {

                // Insertar las variables de sesión correspondientes
                $this->sessionSet('_login_hash', $this->__login_hash); // Insertar el hash de inicio de sesión
                $this->sessionSet('_ip', $this->__ip); // Guardar la dirección IP del usuario
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
    public function msgSet(string $title = "", string $msg = "")
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
 * - checkExtension: Comprueba si una extensión está en el valor de alguno de los tipos de extensión y devuelve la clave y el valor correspondiente
 * icon:Función para obtener el icono correspondiente según el nombre y la extensión de un archivo.
 * - renderIconByType: Función para redenderizar un icono especifico a partir de los argumentos obtenidos.
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
            'isImage' => 'card-image',
            'isVideo' => 'film',
            'isAudio' => 'cassette',
            'isEditable' => [
                'xml' => 'filetype-xml',
                'sql' => 'filetype-sql',
                'json' => 'filetype-json',
                'html' => 'filetype-html',
                'php' => 'filetype-php',
                'md' => 'markdown',
                'css' => 'filetype-css',
                'js' => 'filetype-js',
            ],
            'nonEditable' => [
                'pdf' => 'file-pdf',
                'docx' => 'file-word',
                'xlsx' => 'file-excel',
                'pptx' => 'file-ppt',
                'ttf' => 'fonts',
                'otf' => 'fonts',
                'woff' => 'fonts',
                'woff2' => 'fonts',
                'sqlite3' => 'database',
                'db' => 'database',
                'sqlite' => 'database',
                'zip' => 'file-zip',
            ],
        ];

        if (isset($iconMap[$extType])) {
            if (is_array($iconMap[$extType])) {

                // si $extType es 'isEditable' o 'nonEditable', buscar en el subarray
                if (isset($iconMap[$extType][$fileext])) {
                    $icon = '<i class="bi bi-' . $iconMap[$extType][$fileext] . ' display-3"></i>';
                } else {
                    $icon = '<i class="bi bi-code display-3"></i>';
                }

            } else {
                // si $extType es 'isImage' o 'isVideo', usar el valor directamente
                $icon = '<i class="bi bi-' . $iconMap[$extType] . ' display-3"></i>';
            }
        } else {
            $icon = '<i class="bi bi-code display-3"></i>';
        }

        return $icon;
    }
}

/**
 * Trait Utils
 * Este trait proporciona utilidades para la clase MediaManager.
 * @package MediaManager
 * @category Trait
 */
trait Utils
{
    /**
     * Obtiene la ruta real de un archivo o directorio.
     * @param string $path Ruta del archivo o directorio.
     * @return string|false Ruta real en caso de éxito, o false si falla.
     */
    public function realPath($path)
    {
        $realPath = realpath($path);
        return $realPath ? str_replace('\\', '/', $realPath) : false;
    }

    /**
     * Obtiene la ruta relativa a la raíz del proyecto.
     * @param string $dir Directorio a obtener la ruta relativa.
     * @return string Ruta relativa al directorio en relación a la raíz del proyecto.
     */
    public function rootRelative($dir)
    {
        return ltrim(substr($dir, strlen(ROOT)), '\/');
    }

    /**
     * Obtiene la ruta absoluta a partir de una ruta relativa a la raíz del proyecto.
     * @param string $dir Ruta relativa al directorio.
     * @return string Ruta absoluta correspondiente a la ruta relativa proporcionada.
     */
    public function rootAbsolute($dir)
    {
        return ROOT . ($dir ? '/' . $dir : '');
    }

    /**
     * Configura las cabeceras para permitir peticiones CORS (Cross-Origin Resource Sharing).
     */
    public static function cors()
    {
        // Si se ha recibido el header HTTP_ORIGIN
        if (isset($_SERVER['HTTP_ORIGIN'])) {

            // Establecer los headers Access-Control-Allow-Origin, Access-Control-Allow-Credentials y Access-Control-Max-Age
            header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Max-Age: 86400');
        }

        // Si el método de solicitud es OPTIONS
        if ('OPTIONS' == $_SERVER['REQUEST_METHOD']) {

            // Si se ha recibido el header HTTP_ACCESS_CONTROL_REQUEST_METHOD
            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) {

                // Establecer el header Access-Control-Allow-Methods
                header('Access-Control-Allow-Methods: GET,POST, OPTIONS');
            }

            // Si se ha recibido el header HTTP_ACCESS_CONTROL_REQUEST_HEADERS
            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) {

                // Establecer el header Access-Control-Allow-Headers
                header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
            }

            // Salir del script
            exit(0);
        }
    }

    /**
     * Función para obtener la dirección IP local del equipo.
     *
     * @return string La dirección IP local del equipo.
     */
    public function getDesktopIp(): string
    {
        $localIP = "";
        // Comprobar si la extensión de sockets está cargada en PHP.
        if (extension_loaded('sockets')) {

            // Crear un socket para obtener la dirección IP local del socket.
            $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

            socket_connect($socket, '8.8.8.8', 53); // Conectar el socket a cualquier dirección IP externa y puerto.
            socket_getsockname($socket, $localIP); // Obtener la dirección IP local del socket.
            socket_close($socket); // Cerrar el socket.

        }
        // Devolver la dirección IP local del equipo.
        return ($this->isLocalhost()) ? $localIP : "";
    }

    /**
     * Función que comprueba si la solicitud se está realizando desde un entorno localhost.
     * @return bool Devuelve true si la solicitud se realiza desde localhost, de lo contrario, false.
     */
    public function isLocalhost()
    {
        $is_localhost = false;

        // Comprobar si la dirección IP comienza con "127.0.0." o si el host es "localhost"
        if (strpos($_SERVER['REMOTE_ADDR'], '127.0.0.') === 0 || $_SERVER['HTTP_HOST'] === 'localhost') {
            $is_localhost = true;
        }

        return ($is_localhost) ? true : false;
    }

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
                // Retornamos true si existe
                return (!file_exists($filename)) ? true : false;
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
            return (file_get_contents($filename) == $data) ? true : false;
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
            } else {
                // Si no se logra mover el archivo, se envía un mensaje de error y se redirecciona a la nueva carpeta.
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
     * Url base
     *
     * @return void
     */
    public function urlBase()
    {
        // lista blanca de direcciones IP para localhost
        $whitelist = [
            '127.0.0.1',
            '::1',
        ];

        // Comprobar si la aplicación se está ejecutando en localhost
        if (!in_array($_SERVER['REMOTE_ADDR'], $whitelist)) {

            // construir la URL base usando información del servidor
            $https = (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on') ? 'https://' : 'http://';
            $output = $https . rtrim(rtrim($_SERVER['HTTP_HOST'], '\\/') . dirname($_SERVER['PHP_SELF']), '\\/');
            return $output;

        } else {
            // obtener la URL base desde la configuración
            $output = $this->getOption('Site_url');
            return $output;
        }
    }

    /**
     * Sanitiza el contenido
     *
     * @param string $str
     * @return string
     */
    public function sanitizeContent(string $str = ""): string
    {
        // Sanitiza el contenido con htmlspecialchars
        $sanitizedContents = htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        // Devuelve el contenido sanitizado
        return $sanitizedContents;
    }

    /**
     * Sanitiza el contenido de un archivo
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
        $html = '<details class="debug" style="padding:0;margin:20px auto;"><summary>Debug</summary><div class="details-body "><pre class="p-1 bg-light border">' . $output . '</pre></div></details>';

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
        $value = $value ? urldecode($value) : "";

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
        $breadcrumb = '<nav aria-label="breacrumb"><ol class="breadcrumb rounded-sm" style="background: var(--bs-light);border: 1px solid var(--bs-gray-200);padding: 0.3rem 0.8rem;"><li class="breadcrumb-item active" aria-current="page"><a class="text-decoration-none text-black" href="' . $this->getOption('Site_url') . '">Inicio</a></li>';

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
        $url = (string) $url;
        $st = (int) $st;

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
 * - getDirInfo: Obtener las carpetas y archivos.
 * - getFileInfo: Obtener la información del archivo.
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
    public function getDirInfo(string $dir): array
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
     * @return array Array con información del archivo o array vacio si no se puede obtener la información
     */
    public function getFileInfo(string $filename = ""): array
    {
        if (is_dir($filename) || is_file($filename)) {

            // Obtenemos el tamaño del archivo en bytes
            $filesize = filesize($filename);

            // Obtenemos la fecha de modificación del archivo en formato Unix timestamp
            $filedate = filemtime($filename);

            // Obtenemos los permisos del archivo en octal
            $fileperms = fileperms($filename);
            $extension = pathinfo($filename, PATHINFO_EXTENSION);

            // Comprobamos el tipo de archivo que es
            list("extType" => $extType) = $this->checkExtension($extension);

            // Devolvemos un array con la información del archivo
            return [
                'filepath' => $filename, // Ruta y nombre del archivo
                'fileinfo' => pathinfo($filename), // Información del archivo (nombre, extensión, directorio, etc.)
                'fileperms' => decoct($fileperms&0777), // Permisos del archivo en octal
                'filesize' => $this->formatFileSize($filesize), // Tamaño del archivo en bytes
                'filedate' => date("d-m-Y H:i:s", $filedate), // Fecha de modificación del archivo en formato humano
                'mode' => $extType,
            ];
        }
        return [];
    }
}

/**
 * Trait HtmlView
 * Este trait proporciona funciones para imprimir el html en la página.
 *
 * - viewHead:Generamos el head.
 * - viewHeader:Generamos el header.
 * - viewFooter:Generamos el footer.
 * - viewScripts:Generamos el scripts.
 * - viewLayout:Generamos el layout.
 * ---------------------------------------
 * - defaultView: Generamos la vista por defecto.
 * - editView: Generamos la vista de editar.
 * - uploadFormView: Generamos la vista de subir archivos.
 * - createDirView: Generamos la vista de crear directorio.
 * - removeDirView: Generamos la vista de borrar directorio.
 * - loginView: Generamos la vista del login.
 * - CreateNewEditor: Editor markdown.
 * ----------------------------------------
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
    public function viewHead(string $otherCss = ""): string
    {
        $title = $this->getOption('title'); // Título del sitio web

        // Framework Bootstrap
        $links = '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">';
        $links .= '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">';

        // Si estamos en la vista de edicion cargamos CodeMirror
        if (array_key_exists('get', $_GET) && $this->get('get') == 'file') {
            $links .= '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/codemirror.min.css" />';
            $links .= '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/6.65.7/theme/material-darker.min.css" integrity="sha512-2OhXH4Il3n2tHKwLLSDPhrkgnLBC+6lHGGQzSFi3chgVB6DJ/v6+nbx+XYO9CugQyHVF/8D/0k3Hx1eaUK2K9g==" crossorigin="anonymous" referrerpolicy="no-referrer" />';
        } elseif (array_key_exists('editor', $_GET)) {
            $links .= '<link rel="stylesheet" href="https://unpkg.com/easymde/dist/easymde.min.css">';
            $links .= '<link rel="stylesheet" href="https://cdn.jsdelivr.net/highlight.js/latest/styles/github.min.css">';
            $links .= '<style rel="stylesheet">.editor-preview{--primary:#000;--secondary:#dfdfdf;--background:#fff;--txt:#333;--info:#eefbff;--info-border:#c0def7;--info-txt:#2b5274;--success:#f0ffee;--success-border:#c0f7d8;--success-txt:#2b7434;--success:#fee;--success-border:#f7c0c0;--success-txt:#742b2b;--font-family:Helvetica,arial,sans-serif;--font-size:14px;--font-weight:400;--line-height:1.6;--transition:all .5s ease}.editor-preview{font-family:var(--font-family);font-size:var(--font-size);line-height:var(--line-height);padding-top:10px;padding-bottom:10px;background-color:var(--background);color:var(--txt);padding:30px}.editor-preview blockquote,.editor-preview dl,.editor-preview li,.editor-preview ol,.editor-preview p,.editor-preview pre,.editor-preview table,.editor-preview ul{margin:15px 0}.editor-preview hr{color:var(--secondary);height:4px;padding:0}.editor-preview li{margin:0}.editor-preview ol,.editor-preview ul{padding-left:30px}.editor-preview ol :first-child,ul :first-child{margin-top:0}.editor-preview dl{padding:0}.editor-preview dl dt{font-size:14px;font-weight:700;font-style:italic;padding:0;margin:15px 0 5px}.editor-preview dl dt:first-child{padding:0}.editor-preview dl dt>:first-child{margin-top:0}.editor-preview dl dt>:last-child{margin-bottom:0}.editor-preview dl dd{margin:0 0 15px;padding:0 15px}.editor-preview dl dd>:first-child{margin-top:0}.editor-preview dl dd>:last-child{margin-bottom:0}.editor-preview blockquote{border-left:4px solid var(--secondary);padding:0 15px;color:var(--primary)}.editor-preview blockquote>:first-child{margin-top:0}.editor-preview blockquote>:last-child{margin-bottom:0}.editor-preview table{padding:0;border-collapse:collapse;width:100%;margin:30px auto;background:var(--background)}.editor-preview table tr{border-top:1px solid var(--secondary);background-color:var(--background);margin:0;padding:0}.editor-preview table tr:nth-child(2n){color:var(--primary)}.editor-preview table tr th{font-weight:700;border:1px solid var(--secondary);background:var(--secondary);color:var(--primary);margin:0;padding:6px 13px}.editor-preview table tr td{border:1px solid var(--secondary);margin:0;padding:6px 13px}.editor-preview table tr td :first-child,table tr th :first-child{margin-top:0}.editor-preview table tr td :last-child,table tr th :last-child{margin-bottom:0}.editor-preview img{max-width:100%}.editor-preview tt{margin:0 2px;padding:0 5px;white-space:nowrap;border:1px solid var(--secondary);background-color:var(--background);border-radius:3px}.editor-preview sup{font-size:.83em;vertical-align:super;line-height:0}.editor-preview img{display:block;max-width:100%;margin:20px auto;-webkit-box-shadow:2px 3px 3px var(--background);box-shadow:2px 3px 3px var(--background)}.editor-preview li.task{list-style-type:none}</style>';
        }

        // Retornar la sección head del HTML
        return '<head><meta charset="utf-8"><title>' . $title . '</title><link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>' . $this->getOption('emojiFavicon') . '</text></svg>"><meta name="viewport" content="width=device-width, initial-scale=1.0" /><meta name="application-name" content="' . $this->getOption('title') . '" /><meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"><meta http-equiv="Pragma" content="no-cache"><meta http-equiv="Expires" content="0"><meta name="referrer" content="no-referrer-when-downgrade"><meta name="robots" content="noindex,nofollow">' . $links . '<style rel="stylesheet">:root{--bg-pattern: repeating-conic-gradient( var(--bs-body-bg) 0% 25%, var(--lt-color-gray-200) 0% 50% ) 50% / 20px 20px;}img{max-width:100%;}</style><style rel="stylesheet">' . $otherCss . '</style></head>';
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
    public function viewHeader(string $url, string $title, string $logo, string $homeIcon, string $logoutTpl): string
    {

        $urlHome = ($this->isLogin()) ? '<a class="nav-link" href="' . $url . '">Inicio</a>' : '';

        $urlGeneratePass = ($this->isLogin()) ? '<a class="nav-link" href="' . $url . '?generar=password">Generar</a>' : '';

        return '<header class="header"><nav class="navbar navbar-expand-lg navbar-dark bg-dark"><div class="container-fluid"><a class="navbar-brand" href="' . $url . '"><img class="rounded-pill me-2" src="' . $logo . '" alt="logo"><span>' . $title . '</span></a><button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavAltMarkup" aria-controls="navbarNavAltMarkup" aria-expanded="false" aria-label="Toggle navigation"><span class="navbar-toggler-icon"></span></button><div class="collapse navbar-collapse" id="navbarNavAltMarkup"><div class="navbar-nav ms-auto mb-2 mb-lg-0">' . $urlHome . $urlGeneratePass . $logoutTpl . '</div></div></div></nav><div class="progress rounded-0" style="display:none; height:3px;"><div id="progress-bar" title="Barra de progreso" class="progress-bar bg-danger text-light" role="progressbar" aria-valuenow="25" aria-valuemin="0" aria-valuemax="100" style="height:3px;"></div></header>';
    }

    /**
     * Generamos el footer
     *
     * @return string
     */
    public function viewFooter(): string
    {
        $year = date('Y');
        $ip = $this->getDesktopIp();
        $renderIpTmpl = $ip ? '- <a href="http://' . $ip . '" target="_self" rel="noopener">' . $ip . '</a>' : '';
        return '<footer class="footer mt-4 text-center"><div class="container-fluid"><div class="row"><div class="col-md-12"><p class="copyright"><small>Made with ♥ Moncho Varela © ' . $year . $renderIpTmpl . ' </small></p></div></div></div></footer>';
    }

    /**
     * Generamos el html del javascript
     *
     * @param string $js
     * @return string
     */
    public function viewScripts(string $js): string
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
        } elseif (array_key_exists('editor', $_GET)) {
            $scripts .= '<script src="https://unpkg.com/easymde/dist/easymde.min.js"></script>';
            $scripts .= '<script src="https://cdn.jsdelivr.net/highlight.js/latest/highlight.min.js"></script>';
        }

        $scripts .= '<script rel="javascript">function message(title,msg){const html=`<div class="toast show fixed-top m-2" role="alert" aria-live="assertive" aria-atomic="true" id="msg-notification"><div class="toast-header"><span class="bg-primary p-1 rounded-pill mx-2" style="width:5px;height:5px;"></span><strong class="me-auto">${title}</strong></div><div class="toast-body">${msg}</div></div>`;document.body.innerHTML+=html;let w=setTimeout(()=>{document.getElementById("msg-notification").remove();clearTimeout(w);},2000);}</script>';
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
    public function viewLayout(string $content = "", string $css = "", string $js = "", string $current = "", bool $showHeader = true): string
    {

        $url = $this->urlBase(); // URL del sitio web
        $title = $this->getOption('title'); // Título del sitio web
        $logo = $this->getOption('logo'); // Logo del sitio web
        $homeIcon = '<i class="bi bi-house"></i>'; // Icono

        // Carpeta donde se subirán archivos, si está definida
        $folderToUpload = ($current) ? base64_encode($current) : '';

        // Llamamos a la función createBreadcrumb
        $breadcrumb = ($showHeader) ? $this->createBreadcrumb($current, ROOT) : '';

        // boton de logout que solo sale si estamos logueados
        $logoutTpl = ($this->isLogin()) ? '<a class="nav-link" href="' . $url . '?logout=true">Salir</a>' : '';

        // Llamamos a la función viewHead
        $head = $this->viewHead($css);

        // Llamamos a la función viewHeader
        $header = ($showHeader) ? $this->viewHeader($url, $title, $logo, $homeIcon, $logoutTpl) : '';

        // Llamamos a la función viewFooter
        $footer = $this->viewFooter();

        // Llamamos a la función viewScripts
        $scripts = $this->viewScripts($js);

        // plantilla html
        return '<!Doctype html><html lang="es">' . $head . '<body id="top" data-theme="light"><main id="app">' . $header . '<section class="container-fluid py-3 pb-1"><div class="row"><div class="col-md-12">' . $breadcrumb . '</div></div></section><section class="container-fluid">' . $content . '</section>' . $footer . '</main>' . $scripts . '</body></html>';
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

        // Funciones
        $this->deleteAllFilesForm(); // Borrar archivos selecionados
        $this->zipFilesAndFolders(); // Comprimir archivos selecionados

        $url = $this->getOption('Site_url');
        // Obtener información del directorio
        $scanDir = $this->getDirInfo($dir);

        // Inicializar variable para el HTML generado
        $html = '<form method="post" enctype="multipart/form-data"><input type="hidden" name="folderUrl" value="' . base64_encode($dir) . '"/><div class="btn-group">';

        // Comprobamos que no estamos en root y añadimos el boton volver y los demas botones
        $urlCreateFolder = $url . '?create=dir&where=' . base64_encode($dir);
        $urlCreateFile = $url . '?create=file&where=' . base64_encode($dir);
        $urlUploadFile = $url . '?get=upload&name=' . base64_encode($dir);

        // Comprobamos si estamos en root
        $inRoot = ($this->isRoot($dir)) ? false : true;

        // Si no estamos en root, añadimos el botón para volver
        if ($inRoot) {
            $backToUrl = $url . '?get=dir&name=' . base64_encode(dirname($dir));
            $html .= '<a class="btn btn-light text-primary" href="' . $backToUrl . '" data-bs-toggle="tooltip" data-bs-title="Volver" title="volver"><i class="bi bi-arrow-left"></i></a>';
        }

        // Generamos los botones según si estamos en root o no
        $html .= '<a class="btn btn-light" href="' . $urlUploadFile . '" data-bs-toggle="tooltip" data-bs-title="Subir archivo" title="Subir archivo"><i class="bi bi-upload"></i></a>';
        $html .= '<a class="btn btn-light" href="' . $urlCreateFolder . '" data-bs-toggle="tooltip" data-bs-title="Crear carpeta" title="Crear carpeta"><i class="bi bi-folder"></i></a>';
        $html .= '<a class="btn btn-light" href="' . $urlCreateFile . '" data-bs-toggle="tooltip" data-bs-title="Crear archivo" title="Crear archivo"><i class="bi bi-plus"></i></a>';

        // Si no estamos en root, añadimos el botón para borrar la carpeta
        if ($inRoot) {
            $urlDeleteFolder = $url . '?delete=dir&where=' . base64_encode($dir);
            $html .= '<a class="btn btn-danger" href="' . $urlDeleteFolder . '" data-bs-toggle="tooltip" data-bs-title="Borrar carpeta" title="Borrar carpeta"><i class="bi bi-trash"></i></a>';
        }

        $html .= '</div>'; // Cerramos btn group

        // Opciones de borrar o comprimir
        $html .= '<div class="dropdown float-end"><button class="btn btn-dark dropdown-toggle-no-arrow" type="button" id="dropdownOptions" data-bs-toggle="dropdown" aria-expanded="false" data-bs-toggle="tooltip" data-bs-title="Opciones" title="Opciones"><i class="bi bi-gear"></i></button><ul class="dropdown-menu" aria-labelledby="dropdownOptions"><li><h6 class="dropdown-header">Opciones</h6></li><li><a class="dropdown-item" href="#" id="checkAll">Selecionar todos</a></li><li><input type="submit" onclick="return confirm(\'Estas seguro de comprimir los archivos marcados?\');" name="zipFiles" class="dropdown-item" value="Comprimir marcados" title="Comprimir marcados"/></li><li><input type="submit" onclick="return confirm(\'Estas seguro de borrar los archivos marcados?\');" name="deleteAll" class="dropdown-item text-danger" value="Borrar marcados" title="Borrar marcados"/></li></ul></div>';

        // Agregar contenedor para mostrar los archivos/directorios
        $html .= '<div class="row row-cols-1 row-cols-md-3 row-cols-lg-4 row-cols-xl-5 gy-3 gx-2 my-1">';

        // Si hay archivos/directorios en el directorio, mostrarlos
        $html .= (count($scanDir) > 0) ? "" : "No hay ningún archivo en esta carpeta.";

        foreach ($scanDir as $item) {

            $filepath = base64_encode(ROOT . $item['filepath']);
            $filename = $item['filename'];
            $filetype = $item['filetype'];
            $fileext = $item['fileext'];
            $openFolderIcon = '<i class="bi bi-folder2-open display-3"></i>';
            $icon = '<i class="bi bi-folder display-3"></i>';

            // Si en la url hay un 'root.php' o un 'gallery.php' lo quitamos
            $externalUrl = $this->urlBase() . str_replace(ROOT, '', $item['filepath']);
            $linkToOpen = '';

            // Comprombamos si es un archivo
            if ($filetype == 'file') {
                list("isValid" => $isValid, "extType" => $extType) = $this->checkExtension($fileext);
                $icon = $this->renderIconByType($extType, $fileext, $filetype);
                $openFolderIcon = '<i class="bi bi-pencil"></i>';
                $linkToOpen = '<li><a href="#" onclick="return copyToClipboard(\'' . $externalUrl . '\')" class="dropdown-item">Copiar url</a></li><li><a class="dropdown-item" target="_blank" rel="noopener" href="' . $externalUrl . '" title="Abrir enlace"> Abrir enlace </a></li>';
            }

            // Tipo de archivo
            $typeOfFile = ($filetype == 'file') ? 'archivo' : 'carpeta';
            $editTypeOfFile = ($filetype == 'file') ? "Editar {$typeOfFile}" : "Abrir {$typeOfFile}";

            // Editar si es Markdown
            $editMdFile = ($fileext == 'md') ? '<li><a class="dropdown-item" href="' . $url . '/?editor=create&name=' . $filepath . '" title="' . $editTypeOfFile . ' (md)"> ' . $editTypeOfFile . ' <strong>Md</strong></a></li>' : '<li><a class="dropdown-item" href="' . $url . '/?get=' . $filetype . '&name=' . $filepath . '" title="' . $editTypeOfFile . '"> ' . $editTypeOfFile . ' </a></li>';

            // Dropdown opciones
            $dropdown = '<div class="vert-menu btn-group position-absolute top-0 end-0"><button type="button" class="btn btn-white rounded-0" data-bs-toggle="dropdown" aria-expanded="false" title="Opciones menu"><i class="bi bi-three-dots-vertical"></i></button><ul class="dropdown-menu"> ' . $linkToOpen . ' ' . $editMdFile . ' <li><hr class="dropdown-divider"></li><li><a class="dropdown-item text-danger" href="' . $url . '/?delete=' . $filetype . '&where=' . $filepath . '" title="Borrar elemento"> Borrar ' . $typeOfFile . ' </a></li></ul></div>';

            // Si es un archivo usamos filesv[] y si no foldersv[]
            if ($filetype == 'file') {
                $inputForm = '<input type="checkbox" name="filesv[]" value="' . $item['filepath'] . '" class="me-2 form-check-input"/>';
            } else {
                $inputForm = '<input type="checkbox" name="foldersv[]" value="' . $item['filepath'] . '" class="me-2 form-check-input"/>';
            }

            // Url para las imagenes
            $src = $this->urlBase() . '/' . $this->rootRelative(base64_decode($filepath));

            // Comprobamos si es una imagen
            if ($this->checkIsImage((string) $fileext)) {
                $html .= '<div class="col"><div class="card border-light shadow-sm"><a style="height: 7rem;overflow:hidden;" href="' . $url . '/?get=' . $filetype . '&name=' . $filepath . '"><img loading="lazy" class="card-img-top" src="' . $src . '"/></a><div class="card-body p-0">' . $dropdown . ' </div><div class="card-footer d-flex"> ' . $inputForm . ' <div class="text-truncate" style="width:150px">' . $filename . '</div></div></div></div>';
            } else {
                $html .= '<div class="col"><div class="card border-light shadow-sm"><div class="card-body p-2 py-3 bg-white position-relative"><a href="' . $url . '/?get=' . $filetype . '&name=' . $filepath . '"  class="btn btn-sm btn-link d-flex justify-content-center text-dark">' . $icon . '</a> ' . $dropdown . ' </div><div class="card-footer bg-dark text-light d-flex"> ' . $inputForm . ' <div class="text-truncate" style="width:150px">' . $filename . '</div></div></div></div>';
            }
        }

        // Cerrar contenedor
        $html .= '</div></form>';

        // Detalles del servidor
        $serverDetails = $this->getWebServerDetails();
        $html .= '<div class="server-details">' . $serverDetails . '</div>';
        $js = "const tooltipTriggerList=document.querySelectorAll('[data-bs-toggle=tooltip]');const tooltipList=[...tooltipTriggerList].map(tooltipTriggerEl=>new bootstrap.Tooltip(tooltipTriggerEl));function copyToClipboard(txt){let input=document.createElement('input');input.value=txt;document.body.appendChild(input);input.select();let result=document.execCommand('copy');document.body.removeChild(input);if(result){message('Bien! 😀','Texto copiado al portapapeles')}else{message('Ups! 😯','Error al copiar al portapapeles')}}const checkAllElements=document.getElementById('checkAll');checkAllElements.addEventListener('click',evt=>{evt.preventDefault();checkAllElements.classList.toggle('active');const checkAll=document.querySelectorAll('input[type=checkbox]');if(checkAllElements.classList.contains('active')){Array.from(checkAll).map(item=>item.setAttribute('checked',true))}else{checkAllElements.classList.remove('active');Array.from(checkAll).map(item=>item.removeAttribute('checked'))}},false);";
        // Generamos la plantilla por defecto
        return $this->viewLayout($html, '', $js, $dir);
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
            $html .= '<a class="btn btn-light mb-2" href="' . $backToUrl . '" data-bs-toggle="tooltip" data-bs-title="Volver" title="Volver"><i class="bi bi-arrow-left"></i></a>';
        }

        // Generar el contenido según el tipo de archivo
        $content = "";
        $buttons = "";
        $img = "";
        $download = "";

        // Generar el contenido según el tipo de archivo
        list("isValid" => $isValid, "extType" => $extType) = $this->checkExtension($extension);

        // Ruta de la vista
        $src = $url . '/' . $this->rootRelative($dir);

        $download = '';
        $openExternal = '';
        $contentMap = [
            // Audio
            'isAudio' => '<figure style="background:var(--bg-pattern);" class="text-dark p-2 py-4 m-0 d-flex flex-wrap flex-column justify-content-center align-items-center h-100"><audio loading=lazy controls src="' . $src . '"/><figcaption class="my-2"><code class="bg-dark text-light p-1" style="word-break:break-all">' . $src . '</code></figcaption></figure>',

            // Imagenes
            'isImage' => '<figure style="background:var(--bg-pattern);" class="p-2 py-4 m-0 h-100 d-flex flex-wrap flex-column justify-content-center align-items-center"><img loading=lazy src="' . $src . '" alt="Imagen de carpeta"/><figcaption class="my-2"><code class="bg-dark text-light p-1" style="word-break:break-all">' . $src . '</code></figcaption></figure>',

            // Videos
            'isVideo' => '<div class="p-2 py-4 m-0 text-center justify-content-center flex-column d-flex" style="background:var(--bg-pattern);"><figure class="ratio ratio-16x9"><video loading=lazy controls src="' . $src . '" style="aspect-ratio:16/9"/></figure><code class="bg-dark text-light p-1" style="word-break:break-all">' . $src . '</code></div>',
            // Archivos editables
            'isEditable' => '<textarea name="editor" id="editor">' . $this->sanitizeFileContents($dir) . '</textarea>',

            // Otros archivos
            'nonEditable' => '<div class="ratio ratio-1x1"><iframe loading=lazy src="' . $src . '"></iframe></div>',
        ];

        // Imprime el icono depende del tipo en los archivos no editables
        $icon = $this->renderIconByType($extType, $extension, "file");

        // Comprueba el tipo de extension y enseña el contenido
        if (array_key_exists($extType, $contentMap)) {
            // Comprobamos si la extension es pdf, editable, si es imagen y si es video
            $content = ($extension == 'pdf' || $extType == 'isEditable' || $extType == 'isImage' || $extType == 'isVideo' || $extType == 'isAudio') ? $contentMap[$extType] : '<div class="no-preview h-100 d-flex justify-content-center align-items-center" style="background:var(--bg-pattern);">' . $icon . '</div>';
            // Comprobamos si los permisos del archivo son 666 o 644 si es no editable, si es imagen o si es video
            $download = ($extType == 'nonEditable' || $extType == 'isImage' || $extType == 'isVideo' || $extType == 'isAudio') ? true : false;
            // Comprobamos si no tiene los permisos 666 o 644 si es editable, si es imagen o si es video
            $openExternal = ($extType == 'isEditable' || $extType == 'isImage' || $extType == 'isVideo' || $extType == 'isAudio') ? true : false;
        } else {
            $content = '<div class="no-preview h-100 d-flex justify-content-center align-items-center"  style="background:var(--bg-pattern);">' . $icon . '</div>';
        }

        // Download files
        $downloadTpl = ($download) ? '<a class="btn btn-outline-dark me-1" href="' . $src . '" download data-bs-toggle="tooltip" data-bs-title="Descargar" title="Descargar"><i class="bi bi-download"></i></a>' : '';
        $openExternalTpl = ($openExternal) ? '<a class="btn btn-outline-dark me-1" rel="noopener" target="_blank" href="' . $src . '" data-bs-toggle="tooltip" data-bs-title="Abrir en ventana externa" title="Abrir enlace"><i class="bi bi-box-arrow-up-right"></i></a>' : '';

        // Crear variable para mensaje de confirmación común
        $confirmMessage = "Va a renombrar el archivo {$filename}, ¿está seguro?";

        // Crear variable para HTML común en la sección "Renombrar"
        $renameHtml = '<li class="list-group-item"><details><summary>Renombrar</summary><div class="details-body mt-3"><input type="hidden" name="oldRenameDir" value="' . $dir . '"/><input type="hidden" name="oldRenameFile" value="' . $filename . '.' . $extension . '"/><div class="input-group input-group-sm mb-3"><input type="text" class="form-control" name="newRenameFile" value="' . $filename . '"/><input type="submit" class="btn btn-dark" onclick="return confirm(\'' . $confirmMessage . '\')" name="rename" value="Renombrar"/></div></div></details></li>';

        $folderDir = dirname(str_replace(ROOT . '/', '', $dir));
        $confirmMessageMoveFiles = "Va a mover el archivo {$filename}.{$extension}, ¿está seguro?";

        // Crear una variable para HTML común en la seccion "Mover archivos"
        $moveFilesHtml = '<li class="list-group-item"><details><summary>Mover archivos</summary><div class="details-body mt-3"><input type="hidden" name="old" value="' . $folderDir . '"/><input type="hidden" name="filename" value="' . $filename . '.' . $extension . '"/><div class="input-group input-group-sm mb-3"><input type="text" class="form-control" name="new" value="' . $folderDir . '"/><input type="submit" class="btn btn-dark" onclick="return confirm(\'' . $confirmMessage . '\')" name="move" value="Mover"/></div></div></details></li>';

        // Mensaje para descomprimir
        $confirmMessageUnzipFiles = "Va a descomprimir el archivo {$filename}.{$extension}, ¿está seguro?";
        $unZipFiles = '<li class="list-group-item"><details open><summary>Descomprimir archivos</summary><div class="details-body p-2 bg-light"><input type="hidden" name="oldDirFile" value="' . $folderDir . '"/><input type="hidden" name="fileZipname" value="' . $filename . '.' . $extension . '"/><div class="input-group input-group-sm mb-3"><input type="text" class="form-control" name="newDirFile" value="' . $folderDir . '"/><input type="submit" class="btn btn-light" onclick="return confirm(\'' . $confirmMessageUnzipFiles . '\')" name="unzip" value="Descomprimir"/></div></div></details></li>';

        if ($extType == 'isImage' || $extType == 'isVideo' || $extType == 'nonEditable') {
            $buttons = $renameHtml . $moveFilesHtml . '<li class="list-group-item"><details class="danger"><summary>Borrar</summary><div class="details-body p-2 bg-light"><input type="hidden" name="file" value="' . $dir . '"/><input type="submit" class="btn btn-danger" onclick="return confirm(\'' . $confirmMessage . '\')" name="delete" value="Borrar"/></div></details></li>';
        }

        if ($extType == 'nonEditable' && $extension == 'zip') {
            $buttons = $unZipFiles . $renameHtml . $moveFilesHtml . '<li class="list-group-item"><details><summary>Actualizar</summary><div class="details-body p-2 bg-light"><input type="hidden" name="file" value="' . $dir . '"/><input type="submit" class="btn btn-sm btn-dark" name="update" value="Actualizar"/></div></details></li><li class="list-group-item"><details class="danger"><summary>Borrar</summary><div class="details-body p-2 bg-light"><input type="hidden" name="file" value="' . $dir . '"/><input type="submit" class="btn btn-danger" onclick="return confirm(\'' . $confirmMessage . '\')" name="delete" value="Borrar archivo"/></div></details></li>';
        } else {
            $buttons = $renameHtml . $moveFilesHtml . '<li class="list-group-item"><details><summary>Actualizar</summary><div class="details-body p-2 bg-light"><input type="hidden" name="file" value="' . $dir . '"/><input type="submit" class="btn btn-sm btn-dark" name="update" value="Actualizar"/></div></details></li><li class="list-group-item"><details class="danger"><summary>Borrar</summary><div class="details-body p-2 bg-light"><input type="hidden" name="file" value="' . $dir . '"/><input type="submit" class="btn btn-sm btn-danger" onclick="return confirm(\'' . $confirmMessage . '\')" name="delete" value="Borrar archivo"/></div></details></li>';
        }

        // Datos Exif
        $exifDataInfo = '';
        if ($extType == 'isImage') {
            // Lee los datos Exif de la imagen
            $exifData = $this->imageExif($dir);
            if ($exifData) {
                $exifDataInfo = '<li class="list-group-item active"><details><summary>Exif info</summary><div class="details-body px-3 py-2"><ul class="list-unstyled">';
                foreach ($exifData as $key => $value) {
                    if ($key == 'DateTime') {
                        $exifDataInfo .= '<li><strong>' . $key . ': </strong> ' . date('d-m-Y', $value) . '</li>';
                    } else if ($key == 'DateTimeOriginal') {
                        $exifDataInfo .= '<li><strong>' . $key . ': </strong> ' . date('d-m-Y', $value) . '</li>';
                    } else if ($key == 'gps') {
                        $exifDataInfo .= '<li><strong>Lat: </strong> ' . $value[0] . '</li>';
                        $exifDataInfo .= '<li><strong>Long: </strong> ' . $value[1] . '</li>';
                    } else {
                        $exifDataInfo .= '<li><strong>' . $key . ': </strong> ' . $value . '</li>';
                    }
                }
                $exifDataInfo .= '</ul></div></details></li>';
            }
        }

        // Agregamos las funciones de renombrar,editar y borrar
        $this->runEditViewFunctions();

        // Generar el HTML completo para la vista de edición
        $html .= '<form method="post" style="height:100%"><section class="row"><section class="col-md-8">' . $content . '</section><aside class="col-md-4"><ul class="list-group list-group-flush mb-3 user-select-none"><li class="list-group-item"><strong>Nombre: </strong>' . $filename . '</li><li class="list-group-item"><strong>Extensión: </strong>' . $extension . '</li><li class="list-group-item"><strong>Permisos: </strong>' . $fileperms . '</li><li class="list-group-item"><strong>Tamaño: </strong>' . $filesize . '</li><li class="list-group-item"><strong>Fecha mod. : </strong>' . $filedate . '</li>' . $exifDataInfo . ' ' . $buttons . '</ul></div><div class="card-footer"><div class="btn-group btn-group-sm">' . $downloadTpl . $openExternalTpl . '</div></aside></section></form>';

        // Generar el CSS necesario para la vista de edición
        $css = ".CodeMirror{height: calc(100vh - 10rem);max-height: 100vw;}";

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

        $js = 'document.addEventListener(\'DOMContentLoaded\',()=>{const editorId = document.getElementById("editor"); if(editorId) {const EDITOR=CodeMirror.fromTextArea(editorId,{theme:"material-darker",lineNumbers:true});EDITOR.setOption(\'mode\',\'' . $mode . '\');}},false);';

        $js .= "const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle=\"tooltip\"]');const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))";

        $cadena = $currentFolder;
        return $this->viewLayout($html, $css, $js, $cadena, true);
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
        $html = '<section class="row"><div class="col-md-5"><h3 class="fs-5">Subir archivos en <span class="badge bg-dark">' . $currentFolder . '</span></h3><form enctype="multipart/form-data" id="upload-form"><div class="mb-3"><input type="file" id="file-input" class="form-control" name="files[]" multiple directory="false" required accept="image/*,video/mp4,video/ogg,video/webm,audio/mp3,audio/wav,audio/ogg,audio/aac,.php,text/*,application/*"></div><div class="btn-group"><input type="submit" id="upload-button" class="btn btn-light" value="Subir archivo"><a class="btn btn-danger" href="' . $back . '" data-bs-toggle="tooltip" data-bs-title="Volver" title="Volver">Volver</a></div></form><div id="info"></div></div></div></section>';

        $folderBase = base64_encode($dir);

        $js = 'document.getElementById("upload-form");const e=document.getElementById("file-input"),t=document.getElementById("upload-button"),n=document.getElementById("progress-bar"),l=document.getElementById("info");t.addEventListener("click",(function(t){if(t.preventDefault(),e.value){n.parentElement.style.display="block";const t=new XMLHttpRequest,d=new FormData;for(let t=0;t<e.files.length;t++)d.append("files[]",e.files[t]);t.open("POST","?get=upload&name=' . $folderBase . '"),t.upload.addEventListener("progress",(function(e){const t=100*e.loaded/e.total;n.style.width=t+"%"})),t.addEventListener("load",(function(d){const o=t.responseText;l.innerHTML="<div class=\"alert alert-info my-2 rounded-0\">"+o+"</div>";let a=setTimeout((()=>{e.value="",n.style.width="0%",n.innerText="",n.parentElement.style.display="none",l.innerText="",clearTimeout(a)}),2e3)})),t.send(d)}}));';

        $js .= "const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle=\"tooltip\"]');const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))";

        // Generamos la plantilla
        return $this->viewLayout($html, '', $js, $dir);
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
        $html = '<section class="row"><div class="col-sm-12 col-md-4 col-lg-3 col-xl-4"><h3 class="fs-5"> Crear <strong class="text-primary">' . $name . '</strong> en <span class="badge bg-dark">' . $currentFolder . '</span></h3><form method="POST"><div class="mb-3"><input type="text" class="form-control" name="name" placeholder="Nombre ' . $name . '" required></div><div class="btn-group"><input type="submit" class="btn btn-light" name="create" value="Crear"><a class="btn btn-danger" href="' . $back . '" data-bs-toggle="tooltip" data-bs-title="Volver" title="Volver">Volver</a></div></form></div></section>';

        $js = "const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle=\"tooltip\"]');const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))";

        // Generamos la plantilla
        return $this->viewLayout($html, '', $js, $dir);
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

        // tipo de archivo
        $typeOfFile = $this->get('delete');

        // Obtener la ruta de la carpeta actual
        $currentFolder = str_replace(ROOT, '', $dir);
        $currentFolder = str_replace('//', '/', $currentFolder);
        $currentFolder = $currentFolder ? $currentFolder : '/';

        // Agregamos las funciones
        $this->removeDirFunctions($dir);

        // Creamos el html
        $html = '<section class="row"><div class="col-md-6"><h3> Borrar carpeta</h3><p> Se va a proceder al borrado de la carpeta <br/> <strong>Ruta: </strong> <code>' . $currentFolder . '</code> </p><form method="POST"><input type="hidden" name="' . $typeOfFile . '" value="' . $dir . '"><div class="btn-group"><input type="submit" class="btn btn-light" name="delete" value="Borrar" data-bs-toggle="tooltip" data-bs-title="Borrar archivo"><a class="btn btn-danger" href="' . $url . '" data-bs-toggle="tooltip" data-bs-title="Volver al inicio" title="Volver al inicio">Volver</a></div></form></div></section>';
        $js = "const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle=\"tooltip\"]');const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))";

        // Generamos la plantilla
        return $this->viewLayout($html, '', $js, $dir);
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
        $client_hash = $this->__client_hash;

        // Funciones del login
        $this->loginAuthFunctions($token);

        // html
        $html = '<div class="row"><div class="col-12 col-sm-6 col-md-4 col-xl-3 col-xxl-3 m-auto"><header class="mb-3 my-5"> <img class="rounded-pill me-2" src="' . $logo . '" alt="logo"><span>' . $title . '</span></header><form method="post"> <input type="hidden" name="_captcha" value="' . $captcha . '"/> <input type="hidden" name="_hash" value="' . $client_hash . '"/><div class="mb-3"><label for="password" class="form-label">Contraseña</label> <input type="password" class="form-control" name="password" pattern="^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d\S]{8,}$" placeholder="**********" autocomplete="current-password" required></div><div class="mb-3"><label for="catpcha" class="form-label">Escriba el numero ' . $captcha . ' </label><input type="number" class="form-control" name="captcha" title="captcha" required> </div><div class="mb-3"><button type="submit" class="btn btn-sm btn-light" name="loginAuth"><i class="bi bi-lock me-1"></i><span>Entrar</span></button></div></form></div></div>';

        // generamos el layout
        return $this->viewLayout($html, '', '', $dir, false);
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
        $html = '<section class="row"><div class="col-md-5"><form method="post"><div class="mb-3"><label class="form-label">Generar contraseña</label><input class="form-control" name="pass" placeholder="insame90&?" pattern="^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d\S]{8,}$" required/></div><div class="mb-3 btn-group"><input type="submit" class="btn btn-light" name="generate" value="Generar" data-bs-toggle="tooltip" data-bs-title="Generar" title="Generar"/><a class="btn btn-danger" href="' . $url . '" data-bs-toggle="tooltip" data-bs-title="Volver" title="Vovler">Volver</a></div></form><div class="output"><pre class="bg-dark text-light p-2 shadow rounded-1" style="user-select:all;">' . $output . '</pre></div></div></section>';
        // Javascript
        $js = "const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle=\"tooltip\"]');const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))";

        // Imprimimos el bloque de HTML en la pantalla utilizando la función viewLayout
        echo $this->viewLayout($html, '', $js, ROOT);
    }

    /**
     * Create Markdown editor
     *
     * @param string $filename
     * @return void
     */
    public function createNewEditor(string $filename = ""): void
    {
        // Abrir contenido si existe
        $filename = base64_decode($filename);
        $content = (file_exists($filename) && is_file($filename)) ? file_get_contents($filename) : '..';

        // Obtenemos la URL del sitio utilizando la opción 'Site_url'
        $url = $this->getOption('Site_url');

        // Funcion formulario
        $this->updateMarkdownFile($filename);

        // Sanitizamos
        $content = $this->sanitizeContent($content);

        // Plantilla
        $html = '<section class="row-fluid"><div class="col-12"><form method="post"><textarea name="editor" id="editor" style="min-height:40rem">' . $content . '</textarea> <input type="submit" class="btn btn-sm btn-dark" id="saveContent" name="saveContent" value="Guardar"/> </form></div></section>';
        $script = 'document.addEventListener("DOMContentLoaded",()=>{let editor=document.getElementById("editor");let options=[];if(!esDispositivoMovil()||!esiPhone()){options=[{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleBold,className:"bi bi-type-bold",title:"Negrita"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleItalic,className:"bi bi-type-italic",title:"Italica"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleStrikethrough,className:"bi bi-type-strikethrough",title:"Tachar"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleHeading1,className:"bi bi-type-h1",title:"Cabecera 1"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleHeading2,className:"bi bi-type-h2",title:"Cabecera 2"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleHeading3,className:"bi bi-type-h3",title:"Cabecera 3"},"|",{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleBlockquote,className:"bi bi-quote",title:"Blockquote"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleUnorderedList,className:"bi bi-list-ul",title:"Lista ordenada"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleOrderedList,className:"bi bi-list-ol",title:"Lista Desordenada"},"|",{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawLink,className:"bi bi-link",title:"Enlace"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawImage,className:"bi bi-image-fill",title:"Imagen"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleCodeBlock,className:"bi bi-code",title:"Codigo"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawHorizontalRule,className:"bi bi-hr",title:"Hr"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawTable,className:"bi bi-table",title:"Tabla"},"|",{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.togglePreview,className:"bi bi-eye",title:"Vista previa"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleSideBySide,className:"bi bi-layout-split",title:"Dividir 2 paneles"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleFullScreen,className:"bi bi-fullscreen",title:"Pantalla completa"},"|",{name:"btn btn-sm bg-dark text-light me-1",action:()=>document.getElementById("saveContent").click(),className:"bi bi-save",title:"Guardar"},{name:"btn btn-sm bg-danger text-light",action:()=>history.back(),className:"bi bi-x-square-fill",title:"Salir"}]}else{options=[{name:"others",className:"bi bi-menu-down",title:"others buttons",children:[{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleBold,className:"bi bi-type-bold",title:"Negrita"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleItalic,className:"bi bi-type-italic",title:"Italica"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleStrikethrough,className:"bi bi-type-strikethrough",title:"Tachar"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleHeading1,className:"bi bi-type-h1",title:"Cabecera 1"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleHeading2,className:"bi bi-type-h2",title:"Cabecera 2"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleHeading3,className:"bi bi-type-h3",title:"Cabecera 3"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleBlockquote,className:"bi bi-quote",title:"Blockquote"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleUnorderedList,className:"bi bi-list-ul",title:"Lista ordenada"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleOrderedList,className:"bi bi-list-ol",title:"Lista Desordenada"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawLink,className:"bi bi-link",title:"Enlace"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawImage,className:"bi bi-image-fill",title:"Imagen"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleCodeBlock,className:"bi bi-code",title:"Codigo"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawHorizontalRule,className:"bi bi-hr",title:"Hr"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.drawTable,className:"bi bi-table",title:"Tabla"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.togglePreview,className:"bi bi-eye",title:"Vista previa"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleSideBySide,className:"bi bi-layout-split",title:"Dividir 2 paneles"},{name:"btn btn-sm bg-light text-dark me-1",action:EasyMDE.toggleFullScreen,className:"bi bi-fullscreen",title:"Pantalla completa"}]},"|",{name:"btn btn-sm bg-dark text-light me-1",action:()=>document.getElementById("saveContent").click(),className:"bi bi-save",title:"Guardar"},{name:"btn btn-sm bg-danger text-light",action:()=>history.back(),className:"bi bi-x-square-fill",title:"Salir"}]}let easyMDE=new EasyMDE({element:editor,forceSync:true,lineWrapping:true,minHeight:"30rem",maxHeight:"30rem",spellChecker:false,syncSideBySidePreviewScroll:true,tabSize:4,toolbar:options,renderingConfig:{singleLineBreaks:false,codeSyntaxHighlighting:true}});if(!esDispositivoMovil()||!esiPhone()){easyMDE.toggleFullScreen();easyMDE.toggleSideBySide()}easyMDE.codemirror.options.mode="text/html";highlightCode();easyMDE.codemirror.on("change",highlightCode);function highlightCode(){let codeBlocks=document.querySelectorAll("pre code");codeBlocks.forEach(block=>hljs.highlightBlock(block));editor.value=easyMDE.value()}function esDispositivoMovil(){return/Mobi|Android/i.test(navigator.userAgent)}function esiPhone(){return/iPhone/i.test(navigator.userAgent)}});';
        $css = '.CodeMirror, .CodeMirror-scroll {min-height: 30rem;}.editor-preview pre {padding: 5px;border: 1px solid #222;background: #292929;color: #e3e3e3;}.hljs{display:block;overflow-x:auto;padding:.5em;background:#282a36}.hljs-built_in,.hljs-selector-tag,.hljs-section,.hljs-link{color:#8be9fd}.hljs-keyword{color:#ff79c6}.hljs,.hljs-subst{color:#f8f8f2}.hljs-title,.hljs-attr,.hljs-meta-keyword{font-style:italic;color:#50fa7b}.hljs-string,.hljs-meta,.hljs-name,.hljs-type,.hljs-symbol,.hljs-bullet,.hljs-addition,.hljs-variable,.hljs-template-tag,.hljs-template-variable{color:#f1fa8c}.hljs-comment,.hljs-quote,.hljs-deletion{color:#6272a4}.hljs-keyword,.hljs-selector-tag,.hljs-literal,.hljs-title,.hljs-section,.hljs-doctag,.hljs-type,.hljs-name,.hljs-strong{font-weight:bold}.hljs-literal,.hljs-number{color:#bd93f9}.hljs-emphasis{font-style:italic}';

        // Imprimimos el bloque de HTML en la pantalla utilizando la función viewLayout
        echo $this->viewLayout($html, $css, $script, ROOT, false);
    }
}

/**
 * Trait FormsFunctions
 * Este trait proporciona funciones para los formularios de los views.
 *
 * - updateMarkdownFile: Actualizar archivo Markdown.
 * - loginAuthFunctions: Funcion de login.
 * - removeDirFunctions: Borrar carpeta.
 * - createDirFunctions: Crea un archivo o una carpeta en un directorio específico.
 * - uploadFiles: Subir archivos.
 * - runEditViewFunctions: Funciones para la vista editar.
 *
 * @package MediaManager
 * @category Trait
 */
trait FormsFunctions
{

    /**
     * Actualizar archivo Markdown
     *
     * @param string $filename
     * @return void
     */
    public function updateMarkdownFile(string $filename = "")
    {
        if (array_key_exists('saveContent', $_POST)) {

            // Obtenemos la contraseña ingresada por el usuario en el campo 'pass'
            $content = $_POST['editor'];

            if (file_exists($filename) && is_file($filename)) {
                if (file_put_contents($filename, $content)) {
                    $this->msgSet("Bien 😁", "El archivo se ha editado");
                    $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . base64_encode(dirname($filename)));
                } else {
                    $this->msgSet("Ups 😥", "El archivo no se ha podido editar.");
                    $this->redirect($this->getOption('Site_url') . '?editor=create&name=' . base64_encode($filename));
                }
            } else {
                $this->msgSet("Ups 😥", "El archivo no se ha podido editar.");
                $this->redirect($this->getOption('Site_url') . '?editor=create&name=' . base64_encode($filename));
            }
        }
    }

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
            if ($this->tokenCheck($token) && $this->__client_hash == $this->getPost('_hash', false)) {

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
     * Comprimir archivos
     *
     * @return void
     */
    public function zipFilesAndFolders()
    {
        if ($_SERVER['REQUEST_METHOD'] == 'POST' && array_key_exists('zipFiles', $_POST)) {

            // Url en base64 para redirecionar
            $folderUrl = isset($_POST['folderUrl']) ? $_POST['folderUrl'] : "[]";
            $selectedFiles = isset($_POST['filesv']) ? $_POST['filesv'] : [];
            $selectedFolders = isset($_POST['foldersv']) ? $_POST['foldersv'] : [];

            // Comprobamos que no esten vacios
            if (empty($selectedFiles) && empty($selectedFolders)) {
                $this->msgSet("Ups 😢", "No hay archivos para comprimir");
                exit;
            }

            $filesToCompress = [];

            // Agregar archivos selecionados
            foreach ($selectedFiles as $file) {
                if (file_exists(getcwd() . $file)) {
                    $filesToCompress[] = getcwd() . $file;
                } else {
                    $this->msgSet("Ups 😢", "El archivo {$file} no existe");
                }
            }

            // Agregar archivos de carpetas selecionados
            foreach ($selectedFolders as $folder) {
                if (is_dir(getcwd() . $folder)) {
                    $this->addFilesFromFolder(getcwd() . $folder, $filesToCompress);
                } else {
                    $this->msgSet("Ups 😢", "El carpeta {$folder} no existe");
                }
            }

            // Cremos el archivo Zip
            $zip = new ZipArchive();

            // Nombre del archivo
            $zipName = dirname(reset($filesToCompress)) . '/files_' . uniqid() . '-' . date('d-m-Y') . '.zip';

            // Abrimos y creamos el Zip
            if ($zip->open($zipName, ZipArchive::CREATE) === true) {

                // Agregar archivos
                foreach ($filesToCompress as $file) {
                    $localFile = basename($file);
                    $zip->addFile($file, $localFile);
                }

                // Cerramos el zip
                $zip->close();

                $this->msgSet("Bien 😁", "Se han comprimido los archivos");
                $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . $folderUrl);
            } else {
                $this->msgSet("Ups 😢", "No se han comprimido los archivos");
                $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . $folderUrl);
            }
        }
    }

    /**
     * Función para agregar los archivos de una carpeta al zip
     *
     * @param string $folder
     * @param array $filesToCompress
     * @return void
     */
    public function addFilesFromFolder(string $folder, array&$filesToCompress)
    {
        // Recorremos los directorios
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($folder, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($files as $file) {
            // Comprobamos los archivos y los agregamos
            if ($file->isFile()) {
                $filesToCompress[] = $file->getRealPath();
            }
        }
    }

    /**
     * Borrar archivos y carpetas
     *
     * @return void
     */
    public function deleteAllFilesForm(): void
    {
        if ($_SERVER['REQUEST_METHOD'] == 'POST' && array_key_exists('deleteAll', $_POST)) {

            $folderUrl = isset($_POST['folderUrl']) ? $_POST['folderUrl'] : "";

            $files = isset($_POST['filesv']) ? $_POST['filesv'] : 0;
            $folders = isset($_POST['foldersv']) ? $_POST['foldersv'] : 0;
            // Contadores
            $totalFiles = isset($_POST['filesv']) ? count($files) : 0;
            $totalFolders = isset($_POST['foldersv']) ? count($folders) : 0;

            $filesToDeleteCount = 0; // Contamos los archivos
            $foldersToDeleteCount = 0; // Contamos las carpetas

            // Comprobamos que haya archivos a borrar
            if ($totalFiles > 0) {
                // Borrar archivos
                foreach ($files as $file) {
                    $this->removeFile(ROOT . $file);
                    $filesToDeleteCount++;
                }
            }
            // Comprobamos que haya carpetas a borrar
            if ($totalFolders > 0) {
                // Borrar carpetas
                foreach ($folders as $folder) {
                    $this->removeDir(ROOT . $folder);
                    $foldersToDeleteCount++;
                }
            }
            if ($totalFiles > 0 || $totalFolders > 0) {
                // Redirigimos a la página de destino con un mensaje de éxito o fracaso
                if ($totalFiles == $filesToDeleteCount && $totalFolders == $foldersToDeleteCount) {
                    $this->msgSet("Bien 😁", "Se han borrado  archivos: {$totalFiles} carpetas: {$totalFolders}");
                    $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . $folderUrl);
                } else {
                    $this->msgSet("Oh 🙄", "Hubo un problema, archivos borrados: {$totalFiles}, carpetas:{$totalFolders}");
                    $this->redirect($this->getOption('Site_url' . '?get=dir&name=' . $folderUrl));
                }
            } else {
                $this->msgSet("Oh 🙄", "Tranquilo no se borro nada");
                $this->redirect($this->getOption('Site_url') . '?get=dir&name=' . $folderUrl);
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

            // si es un archivo
            if ($this->getPost('dir')) {
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

            if ($this->getPost('file')) {
                if ($this->removeFile($dir)) {
                    $this->msgSet('Bien 😀', 'El archivo se ha borrado exitosamente.');
                    $url = $this->getOption('Site_url') . '/?get=dir&name=' . base64_encode(dirname($dir));
                    $this->redirect($url);
                }
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

                    if (pathinfo($name, PATHINFO_EXTENSION) == 'md') {
                        $this->redirect($this->getOption('Site_url') . '?editor=create&name=' . base64_encode($dir . '/' . $name));
                    } else {
                        $this->redirect($this->getOption('Site_url') . '?get=file&name=' . base64_encode($dir . '/' . $name));
                    }
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
            $maxFileSize = 100 * 1024 * 1024; // Tamaño máximo permitido en bytes (30 MB)

            // Iteramos sobre cada archivo
            for ($i = 0; $i < $totalFiles; $i++) {

                $filename = $file['name'][$i]; // Obtenemos el nombre del archivo
                $tmpname = $file['tmp_name'][$i]; // Obtenemos la ruta temporal donde se ha guardado el archivo
                $size = $file['size'][$i];

                // Si algún archivo excede el tamaño máximo, muestra un mensaje de error y detiene la ejecución del script.
                if ($size > $maxFileSize) {
                    die("Error 🙄,El tamaño de los archivos subidos no debe exceder de 30 MB.");
                    exit();
                }
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
                    die("Oh 🙄, Hubo un problema al subir el archivo {$filename}");
                }
            }
            // Redirigimos a la página de destino con un mensaje de éxito o fracaso
            if ($uploadedFiles == $totalFiles) {
                die("Bien 😁, La subida de archivos ha tenido exito");
            } else {
                die("Oh 🙄, Hubo un problema al subir el archivo");
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
 * Trait RoutesTrait
 * Controlador de rutas de la app
 */
trait RoutesTrait
{
    /**
     * Punto de entrada de la aplicación
     */
    public function routes()
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
        } elseif (array_key_exists('editor', $_GET)) {
            if ($this->get('editor') === 'create') {
                $filename = (array_key_exists('name', $_GET)) ? $this->get('name') : '...';
                $this->createNewEditor($filename);
            } else {
                // Error, el nombre de la carpeta no existe
                $this->error('Error, el nombre de la carpeta no existe');
            }
        } else {
            // Mostramos la vista por defecto del directorio raíz
            echo $this->defaultView(ROOT);
        }

        // Salir de la aplicación
        if (array_key_exists('logout', $_GET)) {
            $this->logout();
            $this->redirect($this->getOption('Site_url'));
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
    use ExifTrait;
    use Session;
    use Auth;
    use Token;
    use Icons;
    use Utils;
    use FilesystemInfo;
    use HtmlView;
    use FormsFunctions;
    use Msg;
    use RoutesTrait;

    /**
     * Configuracion por defecto
     *
     * @var array
     */
    public static $defaultConfig = [
        'Site_url' => 'http://localhost/root.php',
        'password' => '$2y$10$n5xO5I4XTPt.WZaSGI0x5OEZQoDoBU2dDYrAq8yLXBsb512KfnP2G', // default password demo123;
        'title' => 'App name',
        'logo' => '',
        'emojiFavicon' => '💋',
        'exclude' => ['root', '.gitignore', '.git', 'node_modules', '.htaccess', 'temp', '_temp_files'],
        'imageSupport' => ["tiff", "heic", "ico", "jpg", "JPG", "jpeg", "png", "gif", "svg", "bmp", "webp"],
        'videoSupport' => ["mp4", "webm", "ogg", "mpeg", "mpg", "3gp"],
        'audioSupport' => ["wav", "mp3", "ogg", "m4a"],
        'editableFilesSupport' => ['env', 'less', 'scss', 'jsx', 'ts', 'tsx', 'json', 'sql', 'manifest', 'txt', 'md', 'html', 'htm', 'xml', 'css', 'js', 'php', 'c', 'cpp', 'h', 'hpp', 'py', 'rb', 'java', 'sh', 'pl'],
        'nonEditableFilesSupport' => ["ttf", "otf", "woff", "woff2", "docx", "xlsx", "pptx", "accdb", "pub", "vsd", "doc", "xls", "ppt", "mdb", 'mo', 'po', 'db', 'pdf', 'zip'],
        'allowUrls' => [],
    ];

    /**
     * Configuración
     *
     * @var array
     */
    private $__config = [];

    /**
     * Ip
     *
     * @var string
     */
    private $__ip = "";

    /**
     * Client hash
     *
     * @var string
     */
    private $__client_hash = "";

    /**
     * Login hash
     *
     * @var string
     */
    private $__login_hash = "";

    /**
     * Construct
     *
     * @param array $config
     */
    public function __construct(array $config = [])
    {
        $this->sessionStart();
        // Fusiona el array de configuraciones por defecto con el array de configuraciones que se pasa como argumento en el constructor
        $this->__config = array_merge(self::$defaultConfig, $config);

        // Hash de login y cliente
        foreach (['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'] as $key) {
            $ip = isset($_SERVER[$key]) && !empty($_SERVER[$key]) ? explode(',', $_SERVER[$key])[0] : '';
            if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
                break;
            }
        }

        // datos de seguridad
        $this->__ip = $ip;
        $this->__client_hash = md5($ip . (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '') . __FILE__ . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ''));

        $this->__login_hash = md5($this->getOption('password') . $this->__client_hash);
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
        if (isset($this->__config[$key])) {
            // Si la clave existe, retorna el valor correspondiente
            return $this->__config[$key];
        } else {
            // Si la clave no existe, retorna null
            return null;
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
            return $this->routes();
        } else {
            echo $this->loginView();
        }
    }
}

$MediaManager = new MediaManager($options);
// Iniciamos la aplicación
$MediaManager->run();
