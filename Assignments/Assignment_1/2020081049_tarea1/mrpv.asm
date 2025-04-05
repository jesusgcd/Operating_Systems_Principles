; Establece la dirección de origen del código
[org 0x7E00]

; Indica que el código está en modo de 16 bits
[bits 16]

%define SCREEN 0xB800   ; Define la dirección base de la memoria de video en modo texto

main:
    ; Inicializar pantalla
    mov ax, SCREEN             ; Cargar la dirección base de la memoria de video en AX
    mov es, ax                 ; Establecer ES (segmento extra) a la dirección de la memoria de video
    xor di, di                 ; Limpiar DI (índice destino) para apuntar al inicio de la memoria de video

    ; Ciclo principal
    .loop:
        call crear_cadena_aleatoria     ; Llamar a la función para generar una cadena aleatoria de 4 caracteres
        call menu_juego         ; Llamar a la función para mostrar el menú con la cadena generada
        call perdir_input_usuario   ; Llamar a la función para pedir y validar las respuestas del usuario
        call mostrar_puntaje    ; Llamar a la función para mostrar el puntaje acumulado
        jmp .loop               ; Saltar al inicio del ciclo principal para repetir indefinidamente


; Generar cadena aleatoria de 4 caracteres (a-z, 0-9)
crear_cadena_aleatoria:
    mov si, cadena_aleatoria             ; Establecer SI al inicio de la cadena generada
    mov cx, 4                  ; Establecer el contador de caracteres a generar en 4
    .generar_cadena:
        rdtsc                   ; Leer el contador de tiempo (timestamp counter) para usar como semilla aleatoria
        xor dx, dx              ; Limpiar DX para la división
        mov bx, 36              ; Establecer el divisor en 36 (26 letras + 10 números)
        div bx                  ; Dividir EAX entre 36, el residuo estará en DL
        cmp dl, 26              ; Comparar el residuo con 26
        jl .letra               ; Si es menor que 26, es una letra
        add dl, '0' - 26        ; Convertir residuo a un número (0-9)
        jmp .guardar_cadena     ; Saltar a guardar el carácter
    .letra:
        add dl, 'a'             ; Convertir residuo a una letra (a-z)
    .guardar_cadena:
        mov [si], dl            ; Guardar el carácter generado en la cadena
        inc si                  ; Incrementar SI para apuntar al siguiente carácter en la cadena
        loop .generar_cadena           ; Repetir hasta generar 4 caracteres
    mov byte [si], 0            ; Terminar la cadena con un carácter nulo
    ret                         ; Retornar de la función


; Mostrar menú con la cadena generada
menu_juego:
    mov si, mensaje_bienvenida  ; Cargar la dirección del mensaje de bienvenida en SI
    call imprimir               ; Llamar a la función para imprimir el mensaje de bienvenida
    mov si, cadena_aleatoria              ; Cargar la dirección de la cadena generada en SI
    call imprimir               ; Llamar a la función para imprimir la cadena generada
    mov si, nueva_linea         ; Cargar la dirección de la nueva línea en SI
    call imprimir               ; Llamar a la función para imprimir una nueva línea
    ret                         ; Retornar de la función


; Pedir y validar respuestas del usuario
perdir_input_usuario:
    mov cx, 4                  ; Establecer el contador de caracteres a 4
    mov si, cadena_aleatoria   ; Cargar la dirección de la cadena generada en SI
    .pedir_input:
        push cx                ; Guardar el valor del contador en la pila

        ; Imprimir el carácter actual de la cadena
        mov ah, 0x0E           ; Función de BIOS para imprimir un carácter en modo texto
        mov al, [si]           ; Cargar el carácter actual en AL
        int 0x10               ; Interrupción de BIOS para imprimir el carácter

        ; Imprimir ':'
        mov al, ':'            ; Cargar ':' en AL
        int 0x10               ; Interrupción de BIOS para imprimir ':'

        ; Imprimir ' '
        mov al, ' '            ; Cargar ' ' en AL
        int 0x10               ; Interrupción de BIOS para imprimir ' '

        ; Leer entrada del usuario
        mov di, input_entrada ; Establecer DI al inicio del buffer de entrada
        call leer_input       ; Llamar a la función para leer la entrada del usuario

        ; Validar la entrada del usuario
        call validar_input_usuario ; Llamar a la función para comparar la entrada con la fonética esperada

        pop cx                 ; Recuperar el valor del contador desde la pila
        inc si                 ; Incrementar SI para apuntar al siguiente carácter en la cadena
        loop .pedir_input        ; Repetir hasta que se hayan procesado los 4 caracteres
    ret                        ; Retornar de la función


; Leer entrada del usuario
leer_input:
    pusha                       ; Guardar todos los registros en la pila
    mov cx, 0                   ; Inicializar el contador de caracteres leídos en 0
    .leer:
        mov ah, 0x00            ; Función de BIOS para leer una tecla
        int 0x16                ; Interrupción de BIOS para leer la tecla
        cmp al, 0x0D            ; ¿Es la tecla Enter?
        je .fin                 ; Si es Enter, terminar la lectura
        mov [di], al            ; Guardar el carácter leído en el buffer de entrada
        inc di                  ; Incrementar DI para apuntar al siguiente espacio en el buffer
        inc cx                  ; Incrementar el contador de caracteres leídos
        mov ah, 0x0E            ; Función de BIOS para imprimir un carácter en modo texto
        int 0x10                ; Interrupción de BIOS para imprimir el carácter
        jmp .leer               ; Repetir el proceso para leer el siguiente carácter
    .fin:
    mov byte [di], 0            ; Terminar la cadena con un carácter nulo
    popa                        ; Restaurar todos los registros desde la pila
    ret                         ; Retornar de la función


; Comparar entrada con respuesta esperada
validar_input_usuario:
    pusha
    ; Buscar la palabra fonética del carácter en [si]
    mov al, [si]                ; Cargar el carácter actual de la cadena generada en AL
    mov si, tabla_palabras      ; Cargar la dirección de la tabla fonética en SI
    mov cx, 36                  ; Establecer el contador de caracteres en 36 (26 letras + 10 números)

    ; Convertir AL a índice (0-35)
    cmp al, 'a'                 ; Comparar AL con 'a' para verificar si es una letra
    jl .es_numero               ; Si es menor que 'a', es un número
    sub al, 'a'                 ; Convertir letra a índice (0-25)
    jmp .buscar                 ; Saltar a la búsqueda de la palabra fonética
.es_numero:
    sub al, '0'                 ; Convertir número a índice (26-35)
    add al, 26                  ; Ajustar índice para números

.buscar:
    movzx bx, al                ; Mover el valor de AL a BX con extensión cero
    shl bx, 1                   ; Multiplicar BX por 2 (cada entrada en la tabla es de 2 bytes)
    add si, bx                  ; Sumar BX a SI para obtener la dirección de la palabra fonética
    mov si, [si]                ; Cargar la dirección de la palabra fonética en SI

    ; Comparar la entrada del usuario con la palabra fonética esperada
    mov di, input_entrada      ; Establecer DI al inicio del buffer de entrada del usuario
    call comparar_cadenas       ; Llamar a la función para comparar las cadenas
    jz .es_correcto                ; Si son iguales, saltar a la etiqueta .es_correcto

    ; Incorrecto: mostrar mensaje de error y 0 puntos
    mov si, mensaje_incorrecto           ; Cargar la dirección del mensaje de error en SI
    call imprimir               ; Llamar a la función para imprimir el mensaje de error
    jmp .fin                    ; Saltar a la etiqueta .fin para finalizar

.es_correcto:
    ; Correcto: mostrar mensaje de acierto y sumar 1 punto al puntaje
    mov si, mensaje_correcto         ; Cargar la dirección del mensaje de acierto en SI
    call imprimir               ; Llamar a la función para imprimir el mensaje de acierto
    inc word [contador_puntos]          ; Incrementar el puntaje acumulado en 1

.fin:
    ; Finalizar la comparación y mostrar una nueva línea
    mov si, nueva_linea         ; Cargar la dirección de la nueva línea en SI
    call imprimir               ; Llamar a la función para imprimir una nueva línea
    popa                        ; Restaurar todos los registros desde la pila
    ret                         ; Retornar de la función


; Comparar cadenas en SI (esperada) y DI (entrada)
; Retorna ZF=1 si son iguales
comparar_cadenas:
    pusha                       ; Guardar todos los registros en la pila
.ciclo:
    lodsb                       ; Cargar el siguiente carácter de la cadena esperada en AL
    mov bl, [di]                ; Cargar el siguiente carácter de la cadena de entrada en BL
    inc di                      ; Incrementar DI para apuntar al siguiente carácter de la cadena de entrada
    cmp al, bl                  ; Comparar los caracteres de las dos cadenas
    jne .no_igual               ; Si los caracteres no son iguales, saltar a .no_igual
    test al, al                 ; ¿Es el carácter nulo (fin de cadena)?
    jz .igual                   ; Si es el fin de la cadena, saltar a .igual
    jmp .ciclo                  ; Repetir el ciclo para el siguiente carácter
.no_igual:
    or al, 1                    ; Establecer ZF=0 (cadenas no son iguales)
    jmp .fin                    ; Saltar a .fin
.igual:
    xor al, al                  ; Establecer ZF=1 (cadenas son iguales)
.fin:
    popa                        ; Restaurar todos los registros desde la pila
    ret                         ; Retornar de la función


; Mostrar puntaje
mostrar_puntaje:
    pusha                       ; Guardar todos los registros en la pila
    lea si, mensaje_puntaje     ; Cargar la dirección del mensaje de puntaje en SI
    call imprimir               ; Llamar a la función para imprimir el mensaje de puntaje
    mov ax, [contador_puntos]           ; Cargar el puntaje acumulado en AX
    call imprimir_numero        ; Llamar a la función para imprimir el número del puntaje
    lea si, nueva_linea         ; Cargar la dirección de la nueva línea en SI
    call imprimir               ; Llamar a la función para imprimir una nueva línea
    popa                        ; Restaurar todos los registros desde la pila
    ret                         ; Retornar de la función

; Imprimir número en AX
imprimir_numero:
    pusha                       ; Guardar todos los registros en la pila
    mov cx, 0                   ; Inicializar el contador de dígitos en 0

.convertir:
    xor dx, dx                  ; Limpiar DX para la división
    mov bx, 10                  ; Establecer el divisor en 10
    div bx                      ; Dividir AX entre 10, el residuo estará en DL
    add dl, '0'                 ; Convertir el residuo a su carácter ASCII
    push dx                     ; Guardar el carácter en la pila
    inc cx                      ; Incrementar el contador de dígitos
    test ax, ax                 ; Probar si AX es 0
    jnz .convertir              ; Si AX no es 0, repetir el proceso

.imprimir:
    pop ax                      ; Recuperar el siguiente carácter desde la pila
    mov ah, 0x0E                ; Función de BIOS para imprimir un carácter en modo texto
    int 0x10                    ; Interrupción de BIOS para imprimir el carácter
    loop .imprimir              ; Repetir hasta que todos los caracteres se hayan impreso

    popa                        ; Restaurar todos los registros desde la pila
    ret                         ; Retornar de la función

; Función para imprimir cadenas
; Entrada: SI apunta a la cadena a imprimir
imprimir:
    .ciclo:
        lodsb                   ; Cargar el siguiente byte de la cadena en AL y avanzar SI
        test al, al             ; Probar si el byte es 0 (fin de cadena)
        jz .fin                 ; Si es 0, saltar al final de la función
        mov ah, 0x0E            ; Función de BIOS para imprimir un carácter en modo texto
        int 0x10                ; Interrupción de BIOS para imprimir el carácter en AL
        jmp .ciclo              ; Repetir el ciclo para el siguiente carácter
    .fin:
    ret                         ; Retornar de la función


; Datos
mensaje_bienvenida db 'Bienvenido a MRPV', 0x0D, 0x0A, 'Vamos a deletrear', 0x0D, 0x0A, 'Disfruta del juego', 0x0D, 0x0A, 0
; Mensaje de bienvenida que se mostrará al inicio del programa, seguido de una nueva línea y el texto '¡Vamos a deletrear!'

nueva_linea db 0x0D, 0x0A, 0
; Secuencia de nueva línea (caracteres de retorno de carro y salto de línea)

cadena_aleatoria times 5 db 0
; Espacio reservado para la cadena generada aleatoriamente (4 caracteres + carácter nulo)

input_entrada times 16 db 0
; Buffer para almacenar la entrada del usuario (máximo 15 caracteres + carácter nulo)

contador_puntos dw 0
; Variable para almacenar el puntaje acumulado del usuario


; Esta sección define una tabla fonética que asocia letras y números con sus correspondientes
; representaciones fonéticas. La tabla incluye:
; - Letras de la 'a' a la 'z', cada una asociada con una etiqueta fonética (fon_a, fon_b, etc.).
; - Números del '0' al '9', cada uno asociado con una etiqueta fonética (fon_0, fon_1, etc.).
; Cada entrada en la tabla es una palabra doble (dw) que apunta a la dirección de la etiqueta fonética correspondiente.
; Tabla fonética
tabla_palabras:
    ; Letras a-z
    dw letra_a, letra_b, letra_c, letra_d, letra_e, letra_f, letra_g, letra_h, letra_i
    dw letra_j, letra_k, letra_l, letra_m, letra_n, letra_o, letra_p, letra_q, letra_r
    dw letra_s, letra_t, letra_u, letra_v, letra_w, letra_x, letra_y, letra_z
    ; Números 0-9
    dw numero_0, numero_1, numero_2, numero_3, numero_4, numero_5, numero_6, numero_7, numero_8, numero_9


; Alfabeto de deletreo para radiotelefonía
; Palabras fonéticas
letra_a: db "alfa",0
letra_b: db "bravo",0
letra_c: db "charlie",0
letra_d: db "delta",0
letra_e: db "echo",0
letra_f: db "foxtrot",0
letra_g: db "golf",0
letra_h: db "hotel",0
letra_i: db "india",0
letra_j: db "juliett",0
letra_k: db "kilo",0
letra_l: db "lima",0
letra_m: db "mike",0
letra_n: db "november",0
letra_o: db "oscar",0
letra_p: db "papa",0
letra_q: db "quebec",0
letra_r: db "romeo",0
letra_s: db "sierra",0
letra_t: db "tango",0
letra_u: db "uniform",0
letra_v: db "victor",0
letra_w: db "whiskey",0
letra_x: db "x-ray",0
letra_y: db "yankee",0
letra_z: db "zulu",0
numero_0: db "zero",0
numero_1: db "one",0
numero_2: db "two",0
numero_3: db "three",0
numero_4: db "four",0
numero_5: db "five",0
numero_6: db "six",0       
numero_7: db "seven",0
numero_8: db "eight",0
numero_9: db "nine",0

; Mensajes
mensaje_correcto: db "1 pt",0
mensaje_incorrecto: db "0 pts",0
mensaje_puntaje: db "Puntaje total: ",0