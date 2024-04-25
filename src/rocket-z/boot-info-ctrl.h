/**
 * @file boot-info-ctrl.h
 * @brief Functions to get and update boot information and configuration
 * @details This is normally done by the device to edit image store information, request loading images, affirming images, etc.
 */

#ifndef BOOT_INFO_CTRL_H
#define BOOT_INFO_CTRL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "structs.h"

    /**
     * \brief Load boot information from flash
     * \param buff Pointer to the boot information structure output
     * \return Pointer to the boot information structure. Null if the boot information is invalid.
     */
    struct BootInfo *bootInfo_load(struct BootInfo *buff);

    /**
     * \brief Initialize boot information structure if it was not initialized before
     * \param info Pointer to the boot information structure buffer
     * \return 0 on success, BootError on error
     */
    enum BootError bootInfo_init(struct BootInfo *info);

    /**
     * \brief Save boot information to flash if it has changed
     * \param info Pointer to the boot information structure buffer
     * \return 0 on success, BootError on error
     */
    enum BootError bootInfo_save(const struct BootInfo *info);

    /**
     * \brief Check if image is the one currently loaded
     * \param header Pointer to the image header structure
     * \param bootInfo Pointer to the boot information structure
     * \return true if image is the one currently loaded, false otherwise
     */
    bool appImage_isCurrent(const struct AppImageHeader *header, const struct BootInfo *bootInfo);

    /**
     * \brief Set image address in images store flash
     * \param info Pointer to the image information structure
     * \param type Where the image is stored
     * \param offset Address in flash where the image is stored. must point to image header.
     * \param maxSize Maximum size for storage location
     */
    void bootInfo_setStore(struct AppImageStore *info, enum AppImageStorage storage, size_t offset, size_t maxSize);

    /**
     * \brief Set whethre a store has a valid image
     * \param store Pointer to the image store struct
     * \param status target status
     */
    void bootInfo_setHasImage(struct AppImageStore *store, bool hasImage);

    /**
     * \brief Check if store contains image data
     * \param store Pointer to the image store struct
     * \return true if image is valid, false otherwise
     */
    bool bootInfo_hasImage(const struct AppImageStore *store);

    /**
     * \brief Configure WDT settings. They will take effect after reset. Parameters will not be checked for validity by this function.
     * \param info Pointer to the boot information structure
     * \param timeout Watchdog timeout in milliseconds
     * \param channelCount Number of watchdog channels
     * \param options Device-specific watchdog options.
     * \return 0 on success, 1 if successful but settings are different from currently running configs.
     */
    int bootInfo_setWdt(struct BootInfo *info, uint32_t timeout, uint32_t channelCount, uint32_t options);

    /**
     * \brief Set currently-running image variant name
     * \param info Pointer to the image information structure
     * \param variant Image variant information.
     * \return 0 on success, BootError on error
     */
    enum BootError bootInfo_setCurrentVariant(struct BootInfo *store, const char *variant);

    /**
     * \brief Mark image to be loaded
     * \param store Pointer to store information structure
     */
    void bootInfo_setLoadRequest(struct AppImageStore *store);

    /**
     * \brief Clear image load request
     * \param store Pointer to store information structure
     */
    void bootInfo_clearLoadRequest(struct AppImageStore *store);

    /**
     * \brief Check if image has a load request
     * \param store Pointer to store information structure
     * \return true if image has a load request, false otherwise
     */
    bool bootInfo_hasLoadRequest(const struct AppImageStore *store);

    /**
     * \brief Get fail count
     * \param info Pointer to the boot information structure
     */
    uint32_t bootInfo_getFailCount(const struct BootInfo *info);

    /**
     * \brief Set maximum fail count
     * \param info Pointer to the boot information structure
     * \param count Maximum fail count
     * \return 0 on success, BootError on error
     */
    void bootInfo_setFailCountMax(struct BootInfo *info, uint32_t count);

    /**
     * \brief Raise fail flag for the currently running image. occurs normally before the app runs.
     * \param info Pointer to the boot information structure
     */
    void bootInfo_failFlag(struct BootInfo *info);

    /**
     * \brief Clear fail flag for the currently running image. Must be called by the app to indicate that it has run successfully.
     * \param info Pointer to the boot information structure
     */
    void bootInfo_failClear(struct BootInfo *info);

#ifdef __cplusplus
}
#endif

#endif // BOOT_INFO_CTRL_H