/* $OpenBSD$ */
/*
 * Copyright (c) 2019 Google LLC
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

extern "C" {

#include <sys/types.h>
#include <cstdint>
#include "openssh/ssherr.h"
#include "openssh/ssh-sk.h"

int sshsk_enroll(int, const char*, const char*, const char*, const char*, uint8_t, const char*,
                 struct sshbuf*, struct sshkey**, struct sshbuf*) {
  return SSH_ERR_FEATURE_UNSUPPORTED;
}

int sshsk_sign(const char*, struct sshkey*, u_char**, size_t*, const u_char*, size_t, u_int,
               const char*) {
  return SSH_ERR_FEATURE_UNSUPPORTED;
}

int sshsk_load_resident(const char*, const char*, const char*, u_int, struct sshsk_resident_key***,
                        size_t*) {
  return SSH_ERR_FEATURE_UNSUPPORTED;
}
};
