# Root-Media-Manager
Explorador de archivos en un solo archivo 

## Instalación
Copiar el archivo en el directorio donde se van a crear o editar los archivos.
Si se pone en el directorio principal hay que cambiarle el nombre, por defecto es root.php.
La contraseña por defecto es demo123 y para cambiarla se cambia al final del archivo.
se puede generar una clave nueva en la sección generar.

###  Notas

Si se instala en Raspberry con DietPi puedes renombrar a index.php y usar:

    $MediaManager = new MediaManager([
        'Site_url' => 'http://'.$_SERVER['SERVER_NAME'],
        // ....
    ]);


Funciona con **Php 8.2**