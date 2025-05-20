#include "source/extensions/filters/network/ssh/kex_alg.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

KexAlgorithm::KexAlgorithm(const HandshakeMagics* magics, const Algorithms* algs,
                           const openssh::SSHKey* signer)
    : magics_(magics), algs_(algs), signer_(signer) {
  ASSERT(magics_ != nullptr);
  ASSERT(algs_ != nullptr);
  ASSERT(signer_ != nullptr);
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec