/* Test-only application for copied virtual firmware. Emit an entry marker,
 * then hang before OS selection so recovery requires an owner reset.
 */
#include <efi.h>

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system) {
        (void) image;
        static CHAR16 message[] = L"ParticleVE acceptance: hanging loader entered\r\n";
        system->ConOut->OutputString(system->ConOut, message);
        for (;;)
                __asm__ volatile ("pause");
}
