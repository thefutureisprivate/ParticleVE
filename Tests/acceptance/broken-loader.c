/* Test-only application. Sign only with a key admitted to copied virtual
 * firmware. The direct EFI entry returns before any OS selection/counting.
 */
#include <efi.h>

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *system) {
        (void) image;
        (void) system;
        return EFI_LOAD_ERROR;
}
