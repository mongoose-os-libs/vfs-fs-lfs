/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#pragma once

#include <stdbool.h>

#include "mgos_vfs_dev.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MGOS_VFS_FS_TYPE_LFS "LFS"

/* Returns true if the device contains a SPIFFS filesystem. */
bool mgos_vfs_fs_lfs_probe(struct mgos_vfs_dev *dev);

#ifdef __cplusplus
}
#endif
