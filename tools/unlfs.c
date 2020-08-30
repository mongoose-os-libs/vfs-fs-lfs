/*
 * Copyright (c) 2020 Deomid "rojer" Ryabkov
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "frozen.h"

#include "mem_lfs.h"

static void show_usage(char *argv[]) {
  fprintf(stderr, "usage: %s -f image_file [-l] [-d extdir]\n", argv[0]);
  exit(1);
}

int main(int argc, char **argv) {
  int opt;
  const char *image_file = NULL;
  int list = 0, fs_size = -1, bs = 4096;
  const char *ext_dir = NULL;

  while ((opt = getopt(argc, argv, "b:d:f:lo:")) != -1) {
    switch (opt) {
      case 'b': {
        bs = (size_t) strtol(optarg, NULL, 0);
        if (bs == 0) {
          fprintf(stderr, "invalid fs block size '%s'\n", optarg);
          return 1;
        }
        break;
      }
      case 'd': {
        ext_dir = optarg;
        break;
      }
      case 'f': {
        image_file = optarg;
        break;
      }
      case 'l': {
        list = 1;
        break;
      }
      case 'o': {
        json_scanf(optarg, strlen(optarg), "{size: %u, bs: %u}", &fs_size, &bs);
        break;
      }
    }
  }

  if (image_file == NULL) {
    fprintf(stderr, "-f is required\n");
    show_usage(argv);
  }

  if (mem_lfs_mount_file(image_file, bs) != LFS_ERR_OK) {
    return 1;
  }

  {
    lfs_dir_t d;
    struct lfs_info de;
    lfs_t *fs = mem_lfs_get();
    if (lfs_dir_open(fs, &d, "/") != LFS_ERR_OK) {
      fprintf(stderr, "failed to open root dir\n");
      return 1;
    }
    fprintf(stderr, "reading dir\n");

    while (lfs_dir_read(fs, &d, &de) > 0) {
      if (strcmp(de.name, ".") == 0 || strcmp(de.name, "..") == 0) {
        continue;
      }
      if (list) {
        printf("%s %d\n", de.name, (int) de.size);
      } else if (ext_dir != NULL) {
        char target[1024];
        char *buf = NULL;
        FILE *out;
        lfs_file_t in;

        sprintf(target, "%s/%s", ext_dir, de.name);

        fprintf(stderr, "extracting %s\n", de.name);

        int res = lfs_file_open(fs, &in, de.name, LFS_O_RDONLY);
        if (res < 0) {
          fprintf(stderr, "cannot open LFS file %s, err: %d\n", de.name, res);
          return 1;
        }

        buf = malloc(de.size);
        lfs_ssize_t rr = lfs_file_read(fs, &in, buf, de.size);
        if (rr != (lfs_ssize_t) de.size) {
          fprintf(stderr, "cannot read %s, err: %d\n", de.name, (int) rr);
          return 1;
        }

        lfs_file_close(fs, &in);

        out = fopen(target, "w");
        if (out == NULL) {
          fprintf(stderr, "cannot write %s, err: %d\n", target, errno);
          return 1;
        }

        fwrite(buf, de.size, 1, out);
        free(buf);
        fclose(out);
      }
    }

    lfs_dir_close(fs, &d);
  }

  return 0;
}
