/* Test-only EFI applications for private QEMU firmware and FAT images.
 * The parent records the firmware's LoadImage result, continues through its
 * independent recovery path, and shuts down. No OS or disk writes occur.
 */
#include <efi.h>

static void output_byte(UINT16 port, UINT8 value) {
        __asm__ volatile ("outb %0, %1" : : "a" (value), "Nd" (port));
}

static UINT8 input_byte(UINT16 port) {
        UINT8 value;
        __asm__ volatile ("inb %1, %0" : "=a" (value) : "Nd" (port));
        return value;
}

static void serial_setup(void) {
        output_byte(0x3f9, 0);
        output_byte(0x3fb, 0x80);
        output_byte(0x3f8, 1);
        output_byte(0x3f9, 0);
        output_byte(0x3fb, 3);
        output_byte(0x3fa, 0xc7);
        output_byte(0x3fc, 0x0b);
}

static void serial(const char *message) {
        for (; *message; ++message) {
                for (UINTN wait = 0; wait < 1000000 && !(input_byte(0x3fd) & 0x20); ++wait)
                        __asm__ volatile ("pause");
                output_byte(0x3f8, (UINT8) *message);
        }
}

#ifdef PVE_TRUST_PARENT
static void status(EFI_STATUS value) {
        static const char digits[] = "0123456789abcdef";
        char text[19] = "0x0000000000000000";
        for (UINTN index = 0; index < 16; ++index)
                text[17 - index] = digits[(value >> (4 * index)) & 15];
        serial(text);
        serial("\r\n");
}

static EFI_STATUS candidate_path(EFI_HANDLE image, EFI_SYSTEM_TABLE *system,
                                 EFI_DEVICE_PATH **result) {
        EFI_GUID loaded_guid = LOADED_IMAGE_PROTOCOL;
        EFI_GUID path_guid = DEVICE_PATH_PROTOCOL;
        EFI_LOADED_IMAGE *loaded = NULL;
        EFI_DEVICE_PATH *base = NULL;
        EFI_STATUS error = system->BootServices->HandleProtocol(image, &loaded_guid, (void **) &loaded);
        if (EFI_ERROR(error))
                return error;
        error = system->BootServices->HandleProtocol(loaded->DeviceHandle, &path_guid, (void **) &base);
        if (EFI_ERROR(error))
                return error;

        /* Copy the firmware-owned device path into a bounded, owned allocation.
         * Its final end node is replaced by one fixed candidate-file node.
         */
        UINTN prefix = 0;
        for (;;) {
                if (prefix > 4096 - sizeof(EFI_DEVICE_PATH))
                        return EFI_BAD_BUFFER_SIZE;
                EFI_DEVICE_PATH *node = (EFI_DEVICE_PATH *) ((UINT8 *) base + prefix);
                UINTN size = node->Length[0] | ((UINTN) node->Length[1] << 8);
                if (size < sizeof(EFI_DEVICE_PATH) || size > 4096 - prefix)
                        return EFI_BAD_BUFFER_SIZE;
                if (node->Type == 0x7f && node->SubType == 0xff) {
                        if (size != sizeof(EFI_DEVICE_PATH))
                                return EFI_COMPROMISED_DATA;
                        break;
                }
                prefix += size;
        }
        static CHAR16 name[] = L"\\EFI\\ParticleVE\\candidate.efi";
        UINTN file_size = sizeof(EFI_DEVICE_PATH) + sizeof(name);
        UINTN total = prefix + file_size + sizeof(EFI_DEVICE_PATH);
        UINT8 *path = NULL;
        error = system->BootServices->AllocatePool(EfiLoaderData, total, (void **) &path);
        if (EFI_ERROR(error))
                return error;
        for (UINTN index = 0; index < prefix; ++index)
                path[index] = ((UINT8 *) base)[index];
        EFI_DEVICE_PATH *file = (EFI_DEVICE_PATH *) (path + prefix);
        file->Type = 4;
        file->SubType = 4;
        file->Length[0] = (UINT8) file_size;
        file->Length[1] = (UINT8) (file_size >> 8);
        for (UINTN index = 0; index < sizeof(name); ++index)
                path[prefix + sizeof(EFI_DEVICE_PATH) + index] = ((UINT8 *) name)[index];
        EFI_DEVICE_PATH *end = (EFI_DEVICE_PATH *) (path + prefix + file_size);
        end->Type = 0x7f;
        end->SubType = 0xff;
        end->Length[0] = sizeof(EFI_DEVICE_PATH);
        end->Length[1] = 0;
        *result = (EFI_DEVICE_PATH *) path;
        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system) {
        serial_setup();
        EFI_GUID global = EFI_GLOBAL_VARIABLE;
        static CHAR16 secure_name[] = L"SecureBoot";
        static CHAR16 setup_name[] = L"SetupMode";
        UINT8 secure = 0xff, setup = 0xff;
        UINTN size = sizeof(secure);
        EFI_STATUS error = system->RuntimeServices->GetVariable(secure_name, &global, NULL, &size, &secure);
        if (EFI_ERROR(error) || size != 1 || secure != 1)
                return EFI_SECURITY_VIOLATION;
        size = sizeof(setup);
        error = system->RuntimeServices->GetVariable(setup_name, &global, NULL, &size, &setup);
        if (EFI_ERROR(error) || size != 1 || setup != 0)
                return EFI_SECURITY_VIOLATION;
        serial("ParticleVE trust fixture: secureboot=1 setup=0\r\n");

        EFI_DEVICE_PATH *path = NULL;
        error = candidate_path(image, system, &path);
        if (EFI_ERROR(error)) {
                serial("ParticleVE trust fixture: path_error=");
                status(error);
                return error;
        }
        EFI_HANDLE child = NULL;
        error = system->BootServices->LoadImage(FALSE, image, path, NULL, 0, &child);
        system->BootServices->FreePool(path);
        serial("ParticleVE trust fixture: load_status=");
        status(error);
        if (!EFI_ERROR(error)) {
                UINTN exit_size = 0;
                CHAR16 *exit_data = NULL;
                error = system->BootServices->StartImage(child, &exit_size, &exit_data);
                serial("ParticleVE trust fixture: start_status=");
                status(error);
                if (exit_data)
                        system->BootServices->FreePool(exit_data);
        }
        /* SECURITY_VIOLATION may also return an owned, unstarted image handle. */
        if (child)
                system->BootServices->UnloadImage(child);
        serial("ParticleVE trust fixture: recovery_reached=1\r\n");
        system->RuntimeServices->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
        return EFI_DEVICE_ERROR;
}
#else
EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system) {
        (void) image;
        (void) system;
        serial_setup();
#ifdef PVE_TRUST_CHILD_NEW
        serial("ParticleVE trust fixture: child_entered=new\r\n");
#else
        serial("ParticleVE trust fixture: child_entered=old\r\n");
#endif
        return EFI_SUCCESS;
}
#endif
