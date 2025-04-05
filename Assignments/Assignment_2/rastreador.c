#include <stdio.h>       // Proporciona funciones estándar de entrada y salida como `printf` y `scanf`.
#include <stdlib.h>      // Incluye funciones para la gestión de memoria dinámica, control de procesos y otras utilidades.
#include <string.h>      // Permite manipular cadenas de caracteres, como copiar, concatenar y comparar.
#include <unistd.h>      // Proporciona acceso a la API del sistema POSIX, como llamadas al sistema y funciones de control de procesos.
#include <getopt.h>      // Facilita el análisis de argumentos de línea de comandos.
#include <sys/ptrace.h>  // Permite el uso de ptrace, una herramienta para depurar y rastrear procesos.
#include <sys/types.h>   // Define tipos de datos utilizados en llamadas al sistema.
#include <sys/wait.h>    // Proporciona macros y funciones para manejar procesos hijos y esperar su finalización.
#include <sys/user.h>    // Define estructuras para acceder al contexto de usuario de un proceso rastreado.
#include <sys/reg.h>     // Permite acceder a los registros del procesador en un proceso rastreado.
#include <sys/syscall.h> // Define números de llamadas al sistema para interactuar con el kernel.
#include <signal.h>      // Proporciona funciones para manejar señales, como enviar y capturar interrupciones.

/**
 * @brief Arreglo de nombres de llamadas al sistema.
 *
 * Este arreglo contiene los nombres de las llamadas al sistema, que pueden
 * ser utilizados para mapear números de llamadas al sistema a sus nombres
 * correspondientes.
 * Cada entrada en el arreglo corresponde a una llamada al sistema específica,
 * y el índice de la entrada coincide con el número de la llamada al sistema.
 */
const char *syscall_names[] = {
    [0] = "read",
    [1] = "write",
    [2] = "open",
    [3] = "close",
    [4] = "stat",
    [5] = "fstat",
    [6] = "lstat",
    [7] = "poll",
    [8] = "lseek",
    [9] = "mmap",
    [10] = "mprotect",
    [11] = "munmap",
    [12] = "brk",
    [13] = "rt_sigaction",
    [14] = "rt_sigprocmask",
    [15] = "rt_sigreturn",
    [16] = "ioctl",
    [17] = "pread64",
    [18] = "pwrite64",
    [19] = "readv",
    [20] = "writev",
    [21] = "access",
    [22] = "pipe",
    [23] = "select",
    [24] = "sched_yield",
    [25] = "mremap",
    [26] = "msync",
    [27] = "mincore",
    [28] = "madvise",
    [29] = "shmget",
    [30] = "shmat",
    [31] = "shmctl",
    [32] = "dup",
    [33] = "dup2",
    [34] = "pause",
    [35] = "nanosleep",
    [36] = "getitimer",
    [37] = "alarm",
    [38] = "setitimer",
    [39] = "getpid",
    [40] = "sendfile",
    [41] = "socket",
    [42] = "connect",
    [43] = "accept",
    [44] = "sendto",
    [45] = "recvfrom",
    [46] = "sendmsg",
    [47] = "recvmsg",
    [48] = "shutdown",
    [49] = "bind",
    [50] = "listen",
    [51] = "getsockname",
    [52] = "getpeername",
    [53] = "socketpair",
    [54] = "setsockopt",
    [55] = "getsockopt",
    [56] = "clone",
    [57] = "fork",
    [58] = "vfork",
    [59] = "execve",
    [60] = "exit",
    [61] = "wait4",
    [62] = "kill",
    [63] = "uname",
    [64] = "semget",
    [65] = "semop",
    [66] = "semctl",
    [67] = "shmdt",
    [68] = "msgget",
    [69] = "msgsnd",
    [70] = "msgrcv",
    [71] = "msgctl",
    [72] = "fcntl",
    [73] = "flock",
    [74] = "fsync",
    [75] = "fdatasync",
    [76] = "truncate",
    [77] = "ftruncate",
    [78] = "getdents",
    [79] = "getcwd",
    [80] = "chdir",
    [81] = "fchdir",
    [82] = "rename",
    [83] = "mkdir",
    [84] = "rmdir",
    [85] = "creat",
    [86] = "link",
    [87] = "unlink",
    [88] = "symlink",
    [89] = "readlink",
    [90] = "chmod",
    [91] = "fchmod",
    [92] = "chown",
    [93] = "fchown",
    [94] = "lchown",
    [95] = "umask",
    [96] = "gettimeofday",
    [97] = "getrlimit",
    [98] = "getrusage",
    [99] = "sysinfo",
    [100] = "times",
    [101] = "ptrace",
    [102] = "getuid",
    [103] = "syslog",
    [104] = "getgid",
    [105] = "setuid",
    [106] = "setgid",
    [107] = "geteuid",
    [108] = "getegid",
    [109] = "setpgid",
    [110] = "getppid",
    [111] = "getpgrp",
    [112] = "setsid",
    [113] = "setreuid",
    [114] = "setregid",
    [115] = "getgroups",
    [116] = "setgroups",
    [117] = "setresuid",
    [118] = "getresuid",
    [119] = "setresgid",
    [120] = "getresgid",
    [121] = "getpgid",
    [122] = "setfsuid",
    [123] = "setfsgid",
    [124] = "getsid",
    [125] = "capget",
    [126] = "capset",
    [127] = "rt_sigpending",
    [128] = "rt_sigtimedwait",
    [129] = "rt_sigqueueinfo",
    [130] = "rt_sigsuspend",
    [131] = "sigaltstack",
    [132] = "utime",
    [133] = "mknod",
    [134] = "uselib",
    [135] = "personality",
    [136] = "ustat",
    [137] = "statfs",
    [138] = "fstatfs",
    [139] = "sysfs",
    [140] = "getpriority",
    [141] = "setpriority",
    [142] = "sched_setparam",
    [143] = "sched_getparam",
    [144] = "sched_setscheduler",
    [145] = "sched_getscheduler",
    [146] = "sched_get_priority_max",
    [147] = "sched_get_priority_min",
    [148] = "sched_rr_get_interval",
    [149] = "mlock",
    [150] = "munlock",
    [151] = "mlockall",
    [152] = "munlockall",
    [153] = "vhangup",
    [154] = "modify_ldt",
    [155] = "pivot_root",
    [156] = "_sysctl",
    [157] = "prctl",
    [158] = "arch_prctl",
    [159] = "adjtimex",
    [160] = "setrlimit",
    [161] = "chroot",
    [162] = "sync",
    [163] = "acct",
    [164] = "settimeofday",
    [165] = "mount",
    [166] = "umount2",
    [167] = "swapon",
    [168] = "swapoff",
    [169] = "reboot",
    [170] = "sethostname",
    [171] = "setdomainname",
    [172] = "iopl",
    [173] = "ioperm",
    [174] = "create_module",
    [175] = "init_module",
    [176] = "delete_module",
    [177] = "get_kernel_syms",
    [178] = "query_module",
    [179] = "quotactl",
    [180] = "nfsservctl",
    [181] = "getpmsg",
    [182] = "putpmsg",
    [183] = "afs_syscall",
    [184] = "tuxcall",
    [185] = "security",
    [186] = "gettid",
    [187] = "readahead",
    [188] = "setxattr",
    [189] = "lsetxattr",
    [190] = "fsetxattr",
    [191] = "getxattr",
    [192] = "lgetxattr",
    [193] = "fgetxattr",
    [194] = "listxattr",
    [195] = "llistxattr",
    [196] = "flistxattr",
    [197] = "removexattr",
    [198] = "lremovexattr",
    [199] = "fremovexattr",
    [200] = "tkill",
    [201] = "time",
    [202] = "futex",
    [203] = "sched_setaffinity",
    [204] = "sched_getaffinity",
    [205] = "set_thread_area",
    [206] = "io_setup",
    [207] = "io_destroy",
    [208] = "io_getevents",
    [209] = "io_submit",
    [210] = "io_cancel",
    [211] = "get_thread_area",
    [212] = "lookup_dcookie",
    [213] = "epoll_create",
    [214] = "epoll_ctl_old",
    [215] = "epoll_wait_old",
    [216] = "remap_file_pages",
    [217] = "getdents64",
    [218] = "set_tid_address",
    [219] = "restart_syscall",
    [220] = "semtimedop",
    [221] = "fadvise64",
    [222] = "timer_create",
    [223] = "timer_settime",
    [224] = "timer_gettime",
    [225] = "timer_getoverrun",
    [226] = "timer_delete",
    [227] = "clock_settime",
    [228] = "clock_gettime",
    [229] = "clock_getres",
    [230] = "clock_nanosleep",
    [231] = "exit_group",
    [232] = "epoll_wait",
    [233] = "epoll_ctl",
    [234] = "tgkill",
    [235] = "utimes",
    [236] = "vserver",
    [237] = "mbind",
    [238] = "set_mempolicy",
    [239] = "get_mempolicy",
    [240] = "mq_open",
    [241] = "mq_unlink",
    [242] = "mq_timedsend",
    [243] = "mq_timedreceive",
    [244] = "mq_notify",
    [245] = "mq_getsetattr",
    [246] = "kexec_load",
    [247] = "waitid",
    [248] = "add_key",
    [249] = "request_key",
    [250] = "keyctl",
    [251] = "ioprio_set",
    [252] = "ioprio_get",
    [253] = "inotify_init",
    [254] = "inotify_add_watch",
    [255] = "inotify_rm_watch",
    [256] = "migrate_pages",
    [257] = "openat",
    [258] = "mkdirat",
    [259] = "mknodat",
    [260] = "fchownat",
    [261] = "futimesat",
    [262] = "newfstatat",
    [263] = "unlinkat",
    [264] = "renameat",
    [265] = "linkat",
    [266] = "symlinkat",
    [267] = "readlinkat",
    [268] = "fchmodat",
    [269] = "faccessat",
    [270] = "pselect6",
    [271] = "ppoll",
    [272] = "unshare",
    [273] = "set_robust_list",
    [274] = "get_robust_list",
    [275] = "splice",
    [276] = "tee",
    [277] = "sync_file_range",
    [278] = "vmsplice",
    [279] = "move_pages",
    [280] = "utimensat",
    [281] = "epoll_pwait",
    [282] = "signalfd",
    [283] = "timerfd_create",
    [284] = "eventfd",
    [285] = "fallocate",
    [286] = "timerfd_settime",
    [287] = "timerfd_gettime",
    [288] = "accept4",
    [289] = "signalfd4",
    [290] = "eventfd2",
    [291] = "epoll_create1",
    [292] = "dup3",
    [293] = "pipe2",
    [294] = "inotify_init1",
    [295] = "preadv",
    [296] = "pwritev",
    [297] = "rt_tgsigqueueinfo",
    [298] = "perf_event_open",
    [299] = "recvmmsg",
    [300] = "fanotify_init",
    [301] = "fanotify_mark",
    [302] = "prlimit64",
    [303] = "name_to_handle_at",
    [304] = "open_by_handle_at",
    [305] = "clock_adjtime",
    [306] = "syncfs",
    [307] = "sendmmsg",
    [308] = "setns",
    [309] = "getcpu",
    [310] = "process_vm_readv",
    [311] = "process_vm_writev",
    [312] = "kcmp",
    [313] = "finit_module",
    [314] = "sched_setattr",
    [315] = "sched_getattr",
    [316] = "renameat2",
    [317] = "seccomp",
    [318] = "getrandom",
    [319] = "memfd_create",
    [320] = "kexec_file_load",
    [321] = "bpf",
    [322] = "execveat",
    [323] = "userfaultfd",
    [324] = "membarrier",
    [325] = "mlock2",
    [326] = "copy_file_range",
    [327] = "preadv2",
    [328] = "pwritev2",
    [329] = "pkey_mprotect",
    [330] = "pkey_alloc",
    [331] = "pkey_free",
    [332] = "statx",
    [333] = "io_pgetevents",
    [334] = "rseq",
    [424] = "pidfd_send_signal",
    [425] = "io_uring_setup",
    [426] = "io_uring_enter",
    [427] = "io_uring_register",
    [428] = "open_tree",
    [429] = "move_mount",
    [430] = "fsopen",
    [431] = "fsconfig",
    [432] = "fsmount",
    [433] = "fspick",
    [434] = "pidfd_open",
    [435] = "clone3",
    [436] = "close_range",
    [437] = "openat2",
    [438] = "pidfd_getfd",
    [439] = "faccessat2",
    [440] = "process_madvise",
    [441] = "epoll_pwait2",
    [442] = "mount_setattr",
    [443] = "quotactl_fd",
    [444] = "landlock_create_ruleset",
    [445] = "landlock_add_rule",
    [446] = "landlock_restrict_self",
    [447] = "memfd_secret",
    [448] = "process_mrelease",
    [449] = "futex_waitv",
    [450] = "set_mempolicy_home_node",
    [451] = "cachestat",
    [452] = "fchmodat2",
    [453] = "map_shadow_stack",
    [454] = "futex_wake",
    [455] = "futex_wait",
    [456] = "futex_requeue",
    [457] = "statmount",
    [458] = "listmount",
    [459] = "lsm_get_self_attr",
    [460] = "lsm_set_self_attr",
    [461] = "lsm_list_modules"};

/**
 * @brief Estructura para almacenar el conteo de llamadas al sistema (syscalls).
 *
 * Esta estructura se utiliza para realizar un seguimiento de las llamadas al sistema
 * que se ejecutan en un programa. Cada instancia de esta estructura almacena el nombre
 * de una syscall y la cantidad de veces que ha sido usada.
 *
 * @param name Nombre de la llamada al sistema (syscall).
 * @param count Número de veces que la syscall ha sido ejecutada.
 */
// Estructura para almacenar el conteo de syscalls
typedef struct
{
    char *name;
    int count;
} SyscallCount;

// Tabla de syscalls
// Esta tabla se utiliza para almacenar el conteo de las llamadas al sistema (syscalls)
// que se ejecutan durante la ejecución del programa rastreado. Cada entrada en la tabla
// contiene el nombre de la syscall y la cantidad de veces que ha sido ejecutada.
SyscallCount *syscall_table = NULL;

// Número total de syscalls registradas
// Esta variable lleva un seguimiento del número total de entradas en la tabla de syscalls.
// Se incrementa cada vez que se detecta una nueva syscall que no está previamente registrada.
int total_syscalls = 0;

/**
 * Obtiene el nombre de la llamada al sistema (syscall) correspondiente a un número dado.
 *
 * @param syscall_num El número de la llamada al sistema cuyo nombre se desea obtener.
 * @return Un puntero a una cadena constante que contiene el nombre de la llamada al sistema.
 *         Si el número de syscall no es válido o no está definido, el comportamiento puede variar
 *         dependiendo de la implementación.
 */
const char *get_syscall_name(long syscall_num)
{
    // Comprobar si el número de syscall está dentro del rango válido
    if (syscall_num >= 0 && syscall_num < sizeof(syscall_names) / sizeof(syscall_names[0]))
    {
        // Si el nombre de la syscall está definido, devolverlo; de lo contrario, devolver "desconocido"
        return syscall_names[syscall_num] ? syscall_names[syscall_num] : "desconocido";
    }
    else
    {
        // Si el número de syscall está fuera del rango válido, devolver "desconocido"
        return "desconocido";
    }
}

/**
 * @brief Actualiza el conteo de una llamada al sistema específica en la tabla de syscalls.
 *
 * Esta función incrementa el conteo de una llamada al sistema si ya existe
 * en la tabla de syscalls. Si la llamada al sistema no se encuentra, agrega
 * una nueva entrada para la llamada al sistema redimensionando la tabla e
 * inicializando su conteo a 1.
 *
 * @param syscall_num El número de la llamada al sistema a actualizar.
 *
 * La función realiza los siguientes pasos:
 * 1. Obtiene el nombre de la llamada al sistema usando `get_syscall_name`.
 * 2. Busca la llamada al sistema en la `syscall_table`.
 * 3. Si la encuentra, incrementa el conteo de la entrada correspondiente.
 * 4. Si no la encuentra, redimensiona la `syscall_table` para acomodar una nueva entrada,
 *    agrega el nombre de la llamada al sistema, inicializa su conteo a 1 y actualiza
 *    el número total de llamadas al sistema (`total_syscalls`).
 */
void update_syscall_count(long syscall_num)
{
    // Obtener el nombre de la syscall a partir de su número
    const char *name = get_syscall_name(syscall_num);

    // Buscar si la syscall ya está registrada en la tabla
    for (int i = 0; i < total_syscalls; i++)
    {
        // Comparar el nombre de la syscall con las entradas existentes
        if (strcmp(syscall_table[i].name, name) == 0)
        {
            // Si se encuentra, incrementar el contador de esa syscall
            syscall_table[i].count++;
            return; // Salir de la función, ya que no es necesario agregar una nueva entrada
        }
    }

    // Si la syscall no está registrada, redimensionar la tabla para agregar una nueva entrada
    syscall_table = realloc(syscall_table, (total_syscalls + 1) * sizeof(SyscallCount));

    // Agregar el nombre de la nueva syscall a la tabla
    syscall_table[total_syscalls].name = strdup(name);

    // Inicializar el contador de la nueva syscall a 1
    syscall_table[total_syscalls].count = 1;

    // Incrementar el número total de syscalls registradas
    total_syscalls++;
}

/**
 * @brief Manejador de la señal SIGINT para limpiar la memoria asignada dinámicamente.
 *
 * Esta función se ejecuta cuando el programa recibe la señal SIGINT (Ctrl+C).
 * Libera la memoria asignada para los nombres de las llamadas al sistema y
 * la tabla de llamadas al sistema antes de finalizar el programa.
 *
 * @param sig Señal recibida (en este caso, SIGINT).
 */
void cleanup(int sig)
{
    // Liberar la memoria asignada para los nombres de las syscalls en la tabla
    for (int i = 0; i < total_syscalls; i++)
    {
        free(syscall_table[i].name); // Liberar cada cadena de nombre de syscall
    }

    // Liberar la memoria asignada para la tabla de syscalls
    free(syscall_table);

    // Salir del programa con un código de éxito
    exit(0);
}

/*
 * Variable que indica si se debe habilitar el modo detallado (verbose).
 * Cuando verbose es 1, el programa imprimirá información adicional
 * para facilitar la depuración o el seguimiento de su ejecución.
 * Si es 0, el programa operará en modo silencioso.
 *
 * Variable que indica si el programa debe esperar a que el usuario
 * presione una tecla antes de continuar su ejecución.
 * Esto puede ser útil para pausar el programa en ciertos puntos
 * y permitir al usuario revisar el estado actual antes de proceder.
 * Opciones del rastreador
 */
int verbose = 0;
int wait_for_key = 0;

/**
 * @brief Punto de entrada principal del programa rastreador.
 *
 * Este programa se encarga de realizar las tareas específicas definidas
 * en el contexto del rastreador. La función main procesa los argumentos
 * de línea de comandos y ejecuta la lógica principal del programa.
 *
 * @param argc Número de argumentos pasados por línea de comandos.
 * @param argv Arreglo de cadenas que contiene los argumentos pasados
 *             por línea de comandos. El primer elemento (argv[0]) es
 *             usualmente el nombre del programa.
 *
 * @return Un entero que indica el estado de salida del programa.
 */
int main(int argc, char *argv[])
{

    // Parsear opciones del rastreador (-v y -V)
    int opt;
    while ((opt = getopt(argc, argv, "+vV")) != -1) // Analizar las opciones de línea de comandos
    {
        switch (opt)
        {
        case 'v':        // Si se especifica la opción '-v'
            verbose = 1; // Activar el modo detallado (verbose)
            break;
        case 'V':             // Si se especifica la opción '-V'
            verbose = 1;      // Activar el modo detallado (verbose)
            wait_for_key = 1; // Habilitar la espera de una tecla antes de continuar
            break;
        default: // Si se especifica una opción no válida
            // Imprimir mensaje de error y mostrar el uso correcto del programa
            fprintf(stderr, "Error: Debes especificar un modo valido para ejecutar.\n");
            fprintf(stderr, "Uso: %s [-v] [-V] Prog [opciones de Prog]\n", argv[0]);
            exit(EXIT_FAILURE); // Salir del programa con un código de error
        }
    }

    // En caso de no entrar al while porque no se ingresó una opción, imprimir el mensaje de error
    if (optind == 1) // Si no se procesaron opciones (optind no avanzó)
    {
        // Imprimir mensaje de error indicando que no se especificó un modo de ejecución
        fprintf(stderr, "Error: Debes especificar un modo para ejecutar.\n");
        // Mostrar el uso correcto del programa con las opciones disponibles
        fprintf(stderr, "Uso: %s [-v] [-V] Prog [opciones de Prog]\n", argv[0]);
        // Salir del programa con un código de error
        exit(EXIT_FAILURE);
    }

    // Verificar que haya al menos un argumento después de las opciones (el programa a ejecutar)
    if (optind >= argc) // Si no hay argumentos adicionales después de las opciones
    {
        // Imprimir mensaje de error indicando que no se especificó un programa para ejecutar
        fprintf(stderr, "Error: Debes especificar un programa para ejecutar.\n");
        // Mostrar el uso correcto del programa con las opciones disponibles
        fprintf(stderr, "Uso: %s [-v] [-V] Prog [opciones de Prog]\n", argv[0]);
        // Salir del programa con un código de error
        exit(EXIT_FAILURE);
    }

    // Los argumentos restantes son para el programa a ejecutar
    // Aquí se obtiene un puntero al arreglo de argumentos del programa que se va a rastrear.
    char **prog_args = &argv[optind];

    // Crear un nuevo proceso utilizando fork()
    // El proceso hijo ejecutará el programa especificado, mientras que el proceso padre actuará como rastreador.
    pid_t pid = fork();

    if (pid == 0)
    { // Proceso hijo
        // Habilitar el rastreo del proceso hijo por parte del proceso padre
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // Reemplazar la imagen del proceso hijo con el programa especificado
        execvp(prog_args[0], prog_args);

        // Si execvp falla, imprimir un mensaje de error
        perror("execvp");

        // Salir del proceso hijo con un código de error
        exit(EXIT_FAILURE);
    }
    else if (pid > 0)
    { // Proceso padre (rastreador)
        int status;

        // Esperar a que el proceso hijo cambie de estado
        waitpid(pid, &status, 0);

        // Configurar el manejador de señales para limpiar recursos al recibir SIGINT
        signal(SIGINT, cleanup);

        // Mientras el proceso hijo esté detenido
        while (WIFSTOPPED(status))
        {
            struct user_regs_struct regs;

            // Obtener los registros del proceso hijo
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            // Obtener el número de la syscall desde el registro correspondiente
            long syscall_num = regs.orig_rax;

            // Actualizar el conteo de la syscall en la tabla
            update_syscall_count(syscall_num);

            // Si el modo verbose está activado, mostrar detalles de la syscall
            if (verbose)
            {
                printf("Syscall: %s (PID: %d)\n", get_syscall_name(syscall_num), pid);

                // Si está habilitada la espera por tecla, pausar hasta que el usuario presione una tecla
                if (wait_for_key)
                {
                    printf("Presione una tecla para continuar...");
                    getchar();
                }
            }

            // Continuar la ejecución del proceso hijo hasta la siguiente syscall
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

            // Esperar a que el proceso hijo cambie de estado nuevamente
            waitpid(pid, &status, 0);
        }

        // Imprimir un reporte final con el conteo de todas las syscalls registradas
        printf("\n%-30s %-20s\n", "Nombre del Syscall", "Número de Llamadas");
        printf("----------------------------------------------------------\n");
        int total_calls = 0;
        for (int i = 0; i < total_syscalls; i++)
        {
            printf("%-30s %-20d\n", syscall_table[i].name, syscall_table[i].count);
            total_calls += syscall_table[i].count;
        }
        printf("----------------------------------------------------------\n");
        printf("Total de Syscalls diferentes: %d\n", total_syscalls);
        printf("Total de llamadas a Syscalls: %d\n", total_calls);

        // Liberar la memoria asignada y limpiar recursos
        cleanup(0);
    }
    else
    {
        // Si fork falla, imprimir un mensaje de error
        perror("fork");

        // Salir del programa con un código de error
        exit(EXIT_FAILURE);
    }

    return 0;
}