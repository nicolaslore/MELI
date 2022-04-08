--- Challenge Técnico ---

*******************
** Ejercicio1.py **
*******************

1)
Definir en el sistema operativo las siguientes variables de entorno de sistema:
Nombre: PY_ENV               Valores válidos DEV|PROD
Nombre: PY_LOG_PATH          Path donde se generará el archivo de log durante la ejecución.
Nombre: PY_REPORT_PATH       Path donde se generará el archivo de reporte.
Nombre: PY_INPUT_FILE_PATH   Path donde se encuentra el archivo de entrada.
Nombre: PY_INPUT_FILE_NAME   Nombre del archivo de entrada con extensión.

NOTA 1: Para los paths configurados, el usuario que ejecute el script debe tener permisos de lectura y escritura.
NOTA 2: El archivo de input se completará con un número de orden por línea, sin espacios.
        Ejemplo:
                10000
                10001
                10002
                10003
                

2)
usage: Ejercicio1.py [-h] client_id client_secret redirect_uri code

positional arguments:
  client_id      Id del aplicativo
  client_secret  Secret del aplicativo
  redirect_uri   URL del aplicativo. Ejemplo: https://www.test.com.ar/
  code           Código de seguridad del servidor --> Ejecutar en un navegador por ejemplo: https://auth.mercadolibre.com.ar/authorization?response_type=code&client_id=1111111111111111&redirect_uri=https://www.test.com.ar/ --> En la URL completar con un valor válido luego de    
                 client_id= y redirect_uri= --> Redireccionará la url a una similar a: https://www.test.com.ar/?code=TG-624f9bb66d485a001a3a0900-129862714 --> Copiar el código: TG-624f9bb66d485a001a3a0900-129862714

optional arguments:
  -h, --help     show this help message and exit