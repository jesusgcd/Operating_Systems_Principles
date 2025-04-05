[org 0x7C00]  ; Indicar al ensamblador que el código se cargará en la dirección 0x7C00
[bits 16]     ; Indicar al ensamblador que el código es de 16 bits

start:
    ; Configurar segmentos
    xor ax, ax          ; Poner AX en 0 para inicializar los registros de segmento
    mov ds, ax          ; Configurar el segmento de datos (DS) en 0
    mov es, ax          ; Configurar el segmento extra (ES) en 0

    ; Cargar el MBR desde el segundo sector (sector 2) del disco
    mov ah, 0x02        ; Función de lectura de disco (BIOS interrupt 13h)
    mov al, 1           ; Número de sectores a leer (1 sector)
    mov ch, 0           ; Cilindro 0 (parte alta del CHS)
    mov cl, 2           ; Sector 2 (parte baja del CHS)
    mov dh, 0           ; Cabeza 0 (parte media del CHS)
    mov dl, 0x80        ; Primera unidad de disco duro (0x80 es el primer disco duro)
    mov bx, 0x7E00      ; Dirección de carga en memoria (después del bootloader)
    int 0x13            ; Llamar a la interrupción de BIOS para leer el sector

    jc disk_error       ; Saltar a la rutina de manejo de errores si hay un error (CF = 1)

    jmp 0x7E00          ; Saltar a la dirección de carga del MBR para continuar la ejecución

disk_error:
    ; Manejar el error (por ejemplo, mostrar un mensaje de error)
    mov si, error_msg    ; Cargar la dirección del mensaje de error en SI
    call imprimir        ; Llamar a la rutina de impresión para mostrar el mensaje de error
    hlt                  ; Detener la ejecución del sistema

imprimir:
    .ciclo:
        lodsb               ; Cargar el siguiente byte de la cadena apuntada por SI en AL y avanzar SI
        test al, al         ; Probar si AL es 0 (fin de la cadena)
        jz .fin             ; Si AL es 0, saltar a la etiqueta .fin
        mov ah, 0x0E        ; Función de BIOS para imprimir un carácter en modo texto
        int 0x10            ; Llamar a la interrupción de BIOS para imprimir el carácter en AL
        jmp .ciclo          ; Repetir el ciclo para el siguiente carácter
    .fin:
    ret                    ; Retornar de la subrutina

error_msg db 'Error al leer el disco', 0  ; Mensaje de error terminado en 0

times 510-($-$$) db 0   ; Rellenar con ceros hasta alcanzar 510 bytes
dw 0xAA55               ; Firma del bootloader (2 bytes), totalizando 512 bytes