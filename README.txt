Istruzioni su come far funzionare tutto:

1. QEMU

	1.1 scaricare da github: git clone https://github.com/qemu/qemu.git
	1.2 NON fare checkout a nessuna versione
	1.3 scaricare tutte le dipendenze necessarie
		sudo apt-get install autoconf automake autotools-dev curl libmpc-dev libmpfr-dev libgmp-dev \
                 gawk build-essential bison flex texinfo gperf libtool patchutils bc \
                 zlib1g-dev libexpat-dev git ninja-build libpixman-1-dev

	1.4 eseguire i comandi:
		cd qemu
		./configure --target-list=riscv64-softmmu --enable-slirp --enable-debug
		make
2. BUILDROOT

	2.1 scaricare da github: git clone https://github.com/buildroot/buildroot.git
	2.2 eseguire i comandi:
		cd buildroot
		make qemu_riscv64_virt_defconfig
		make
	2.3 NON REBUILDARE MAI PIÙ BUILDROOT
	2.4 in buildroot/output/images modificare start-qemu.sh in modo che prima di qemu-system-riscv64 ci sia tutto il percorso che arriva fino a qemu/build
	2.5 avviare QEMU per la prima volta con ./start-qemu.sh (non ho mai capito se è uno step necessario, ma l'ho sempre fatto, quindi boh)


3. DISPOSITIVO

	3.1 aprire qemu/hw/misc/Kconfig e aggiungere le righe:
		config CRYPTO_CORE
			bool
	    
	    in una posizione relativamente arbitraria
	3.2 copiare il file crypto_core.c (cartella qemu) in qemu/hw/misc/
	3.3 modificare il file qemu/hw/misc/meson.build aggiungendo la riga:
		softmmu_ss.add(when: 'CONFIG_BANANA_ROM', if_true: files('banana_rom.c'))
	    in una posizione arbitraria, tra le prime. 
	    SE AL POSTO DI softmmu_ss C'È SCRITTO ALTRO, VA BENE LO STESSO
	3.4 modificare il file qemu/hw/riscv/Kconfig aggiungendo la riga:
		select CRYPTO_CORE
	    nell'elenco dei "select" che seguono "config RISCV_VIRT"
	3.5 copiare il file crypto_core.h (cartella qemu) in qemu/include/hw/misc/
		N.B. CARTELLA DIVERSA DAL .c
	3.6 modificare il file qemu/include/hw/riscv/virt.h aggiungendo:
		VIRT_CRYPTO_CORE
	    nel primo "enum" (dove ci sono gli altri VIRT_ per intenderci, senza nessun IRQ)
	3.7 modificare il file qemu/hw/riscv/virt.c eseguendo vari passaggi. Guardare il file virt.c nella cartella qemu per reference.
		- aggiungere #include "hw/misc/banana_rom.h" tra gli include
		- aggiungere [VIRT_CRYPTO_CORE] = {0x8000000, 0x200}, in static const MemMapEntry virt_memmap[] (non dimenticare la virgola)
		- aggiungere crypto_core_create(memmap[VIRT_CRYPTO_CORE].base); nella funzione virt_machine_init appena dopo la riga sifive_test_create(memmap[VIRT_TEST].base);

		- dichiarare la funzione seguente appena prima della riga static void create_fdt(...



static void create_fdt_crypto_core(RISCVVirtState *s, const MemMapEntry *memmap, uint32_t irq_mmio_phandle)
{
    MachineState *ms = MACHINE(s);
    char *nodename;
    hwaddr base = memmap[VIRT_CRYPTO_CORE].base;
    hwaddr size = memmap[VIRT_CRYPTO_CORE].size;
    nodename = g_strdup_printf("/crypto_core@%" PRIx64, base);

    qemu_fdt_add_subnode(ms->fdt, nodename);
    qemu_fdt_setprop_string(ms->fdt, nodename, "compatible", "crypto-core");
    qemu_fdt_setprop_sized_cells(ms->fdt, nodename, "cryptoreg", 2, base, 2, size);
    qemu_fdt_setprop_cells(ms->fdt, nodename, "interrupt-parent", irq_mmio_phandle);

    g_free(nodename);
}



		- nella funzione static void create_fdt(... , appena dopo la riga create_fdt_fw_cfg(s, memmap); scrivere la riga:
			create_fdt_crypto_core(s, memmap, irq_mmio_phandle);

Fatto tutto questo, ribuildare QEMU (e non BUILDROOT) rieseguendo i comandi a 1.4.



4. DRIVER E PROGRAMMA

	4.1 aprire la cartella driver e modificare, nei file 'Makefile' e 'comando_make.txt', i percorsi alle proprie cartelle ed eventualmente il nome del compiler se diverso
	4.2 eseguire il comando in 'comando_make.txt' per creare il file crypto-core.ko
	4.3 passare il file crypto-core.ko all'interno di qemu (qualunque directory) ed eseguire il comando:	
		insmod crypto-core.ko
	    una scritta dovrebbe confermarne l'inserimento.
	4.4 aprire la cartella test_program e cambiare nel Makefile il percorso e il nome del compilatore come prima
	4.5 con il comando make, creare il file test_program.o
	4.6 passare il file test_program.o all'interno di qemu (qualunque directory) ed eseguire il comando:
		chmod 777 test_program.o
	4.7 avviare il programma di test, con i parametri richiesti ( ./test_program.o CHIAVE(32 caratteri) IV(16 caratteri) INPUT(16 caratteri) MODE(0 o 1) FORMAT(da 0 a 2) )
		