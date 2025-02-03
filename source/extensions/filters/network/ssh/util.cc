#include "source/extensions/filters/network/ssh/util.h"

extern "C" {
#include "openssh/cipher.h"
}

namespace libssh {

template <> void delete_impl(struct sshkey* t) { sshkey_free(t); }
template <> void delete_impl(struct sshbuf* t) { sshbuf_free(t); }
template <> void delete_impl(struct sshcipher_ctx* t) { cipher_free(t); }

} // namespace libssh