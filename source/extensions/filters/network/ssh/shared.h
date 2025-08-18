#pragma once

#include "source/extensions/filters/network/ssh/transport.h"
#include <memory>

#pragma clang unsafe_buffer_usage begin
#include "source/common/common/thread.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/thread_local/thread_local_object.h"
#include "envoy/network/socket_interface.h"
#include "source/extensions/io_socket/user_space/io_handle_impl.h"
#include "source/common/stream_info/filter_state_impl.h"
#include "envoy/server/factory_context.h"
#pragma clang unsafe_buffer_usage end

#include "source/extensions/filters/network/ssh/wire/util.h"
#include "absl/strings/str_replace.h"
#include "absl/container/node_hash_set.h"
#include "source/extensions/filters/network/ssh/common.h"
#include "source/extensions/filters/network/ssh/wire/messages.h"
#include "source/extensions/filters/network/ssh/filter_state_objects.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

using Envoy::Event::Dispatcher;
using Envoy::Event::FileReadyType;
using Envoy::Event::PlatformDefaultTriggerType;
using pomerium::extensions::ssh::ChannelEvent;

class UpstreamDelegateCallbacks {
public:
  virtual ~UpstreamDelegateCallbacks() = default;
  virtual void onStreamEnd(std::string_view reason) PURE;
};

class ExternalChannel : public SshMessageDispatcher {
public:
  ExternalChannel(TransportCallbacks& transport, uint32_t channel_id, Dispatcher* dispatcher,
                  Network::IoHandlePtr io_handle, StreamInfo::FilterStateImpl passthrough_filter_state)
      : transport_(transport),
        channel_id_(channel_id),
        transport_dispatcher_(dispatcher),
        io_handle_(std::move(io_handle)),
        passthrough_filter_state_(std::move(passthrough_filter_state)) {

    transport_dispatcher_->post([this] {
      io_handle_->initializeFileEvent(*transport_dispatcher_, [this](uint32_t events) { return onFileEvent(events); }, PlatformDefaultTriggerType, FileReadyType::Read | FileReadyType::Closed);
    });

    ChannelEvent ev;
    auto* opened = ev.mutable_external_channel_opened();
    opened->set_channel_id(channel_id_);
    downstream_address_ = passthrough_filter_state_.getDataReadOnly<Network::AddressObject>(DownstreamSourceAddressFilterStateFactory::key());
    opened->set_remote_address(downstream_address_->address()->asString());
    sendChannelEvent(ev);
  }

  void sendChannelEvent(const ChannelEvent& event) {
    if (auto stream = transport_.authState().hijacked_stream.lock(); stream) {
      ChannelMessage msg;
      *msg.mutable_channel_event() = event;
      stream->sendMessage(msg, false);
    }
  }

  uint32_t channelId() const { return channel_id_; }

  std::string_view downstreamAddress() const {
    return downstream_address_->address()->asStringView();
  }

  // write a message to the channel
  void writeMessage(wire::Message&& msg) {
    ASSERT(transport_dispatcher_->isThreadSafe());
    ENVOY_LOG_MISC(info, "sending message on ExternalChannel {}: {}", channel_id_, msg.msg_type());
    transport_dispatcher_->post([msg = std::move(msg), this] mutable {
      auto r = transport_.sendMessageToConnection(std::move(msg));
      if (!r.ok()) {
        ENVOY_LOG_MISC(error, "sendMessageToConnection failed: {}", r.status());
        return;
      }
      ENVOY_LOG_MISC(info, "sendMessageToConnection ok: {} bytes", *r);
    });
  }

  // handle a message read from the channel
  void readMessage(wire::Message&& msg) {
    ASSERT(transport_dispatcher_->isThreadSafe());
    ENVOY_LOG_MISC(info, "read message on ExternalChannel {}: {}", channel_id_, msg.msg_type());
    auto stat = msg.visit(
      [this](wire::ChannelDataMsg& data_msg) {
        if (waiting_on_socks5_ > 0) {
          if (waiting_on_socks5_ == 2) {
            if (data_msg.data->size() != 2 ||
                data_msg.data[0] != 0x05 ||
                data_msg.data[1] != 0x00) {
              return absl::InvalidArgumentError("invalid SOCKS5 reply");
            }
            waiting_on_socks5_--;
            return absl::OkStatus();
          }
          if (data_msg.data->size() != 10 || data_msg.data[0] != 0x05) {
            return absl::InvalidArgumentError("invalid SOCKS5 reply");
          }
          return with_buffer_view(*data_msg.data, [this](Buffer::Instance& resp) {
            uint8_t command = resp.peekInt<uint8_t>(1);
            uint8_t reserved = resp.peekInt<uint8_t>(2);
            uint8_t address_type = resp.peekInt<uint8_t>(3);
            uint32_t addr = resp.peekBEInt<uint32_t>(4);
            uint16_t dst_port = resp.peekBEInt<uint8_t>(8);
            if (command != 0x00) { // SSH_SOCKS5_SUCCESS
              return absl::InvalidArgumentError("SOCKS5 connect request failed");
            } else if (address_type != 0x01) { // SSH_SOCKS5_IPV4
              return absl::InvalidArgumentError("SOCKS5 reply contained wrong address type");
            }
            (void)reserved;
            ENVOY_LOG_MISC(info, "SOCKS5 connect success: addr={}, port={}", inet_ntoa(*reinterpret_cast<struct in_addr*>(&addr)), dst_port);
            waiting_on_socks5_--;
            return absl::OkStatus();
          });
        }
        Buffer::OwnedImpl buffer(data_msg.data->data(), data_msg.data->size());
        auto r = io_handle_->write(buffer);
        if (!r.ok()) {
          ENVOY_LOG_MISC(error, "write: io error: {}", r.err_->getErrorDetails());
          return absl::OkStatus();
        }
        ENVOY_LOG_MISC(info, "wrote {} bytes to socket", r.return_value_);
        return absl::OkStatus();
      },
      [this](wire::ChannelEOFMsg&) {
        ENVOY_LOG_MISC(error, "got eof message");
        io_handle_->shutdown(SHUT_WR);
        return absl::OkStatus();
      },
      [this](wire::ChannelCloseMsg&) {
        ENVOY_LOG_MISC(error, "got close message");
        io_handle_->shutdown(SHUT_WR);
        return absl::OkStatus();
      },
      [&msg](auto&) {
        ENVOY_LOG_MISC(error, "unexpected message received on channel: {}", msg.msg_type());
        return absl::InvalidArgumentError("unexpected message received on channel");
      });
    // TODO
    stat.IgnoreError();
  }

  int waiting_on_socks5_{0}; // XXX this is terrible
  void demoSendSocks5Connect() {
    waiting_on_socks5_ = 2;
    Buffer::OwnedImpl msg;
    {
      msg.writeByte<uint8_t>(0x05); // socks5
      msg.writeByte<uint8_t>(0x01); // number of auth methods (1)
      msg.writeByte<uint8_t>(0x00); // SSH_SOCKS5_NOAUTH

      wire::ChannelDataMsg dataMsg;
      dataMsg.data = wire::flushTo<bytes>(msg);
      dataMsg.recipient_channel = channel_id_;
      transport_.sendMessageToConnection(std::move(dataMsg)).IgnoreError(); // TODO
    }

    {
      // next message
      msg.writeByte<uint8_t>(0x05); // socks5
      msg.writeByte<uint8_t>(0x01); // SSH_SOCKS5_CONNECT
      msg.writeByte<uint8_t>(0x00); // reserved
      msg.writeByte<uint8_t>(0x01); // address type: SSH_SOCKS5_IPV4
      // write 4 bytes for the address (in_addr big endian), and 2 bytes for the port
      msg.writeByte<uint8_t>(127);
      msg.writeByte<uint8_t>(0);
      msg.writeByte<uint8_t>(0);
      msg.writeByte<uint8_t>(1);
      msg.writeBEInt<uint16_t>(12345);

      wire::ChannelDataMsg dataMsg;
      dataMsg.data = wire::flushTo<bytes>(msg);
      dataMsg.recipient_channel = channel_id_;
      transport_.sendMessageToConnection(std::move(dataMsg)).IgnoreError(); // TODO
    }
  }

  absl::Status onFileEvent(uint32_t events) {
    ASSERT(transport_dispatcher_->isThreadSafe());
    if ((events & FileReadyType::Closed) != 0) {
      return onClose();
    }

    absl::Status status;
    if ((events & FileReadyType::Read) != 0) {
      status = readReady();
    }

    if (!status.ok()) {
      return status;
    }

    // if ((events & FileReadyType::Write) != 0) {
    //   status = writeReady();
    // }

    return status;
  }

  absl::Status onClose() {
    ChannelEvent ev;
    auto* opened = ev.mutable_external_channel_closed();
    opened->set_channel_id(channel_id_);
    sendChannelEvent(ev);
    //   ASSERT(transport_dispatcher_->isThreadSafe());
    //   auto r = io_handle_->close();
    //   if (!r.ok()) {
    //     return absl::CancelledError(fmt::format("close: io error: {}", r.err_->getErrorDetails()));
    //   }
    // ENVOY_LOG_MISC(info, "socket closed", r.return_value_);
    return absl::OkStatus();
  }

  absl::Status readReady() {
    ASSERT(transport_dispatcher_->isThreadSafe());
    // Read from the transport socket and encapsulate the data into a ChannelData message, then
    // write it on the channel
    Buffer::OwnedImpl buffer;
    auto r = io_handle_->read(buffer, std::nullopt);
    if (!r.ok()) {
      return absl::CancelledError(fmt::format("read: io error: {}", r.err_->getErrorDetails()));
    }
    wire::ChannelDataMsg dataMsg;
    dataMsg.recipient_channel = channel_id_;
    dataMsg.data = wire::flushTo<bytes>(buffer);
    writeMessage(wire::Message{std::move(dataMsg)});
    return absl::OkStatus();
  }

private:
  TransportCallbacks& transport_;
  uint32_t channel_id_;
  Dispatcher* transport_dispatcher_;
  Network::IoHandlePtr io_handle_;
  StreamInfo::FilterStateImpl passthrough_filter_state_;
  const Network::AddressObject* downstream_address_;
};

class ActiveStreamCallbacks {
public:
  virtual ~ActiveStreamCallbacks() = default;
  virtual void requestOpenDownstreamChannel(Network::IoHandlePtr io_handle) PURE;
};

using ActiveStreamCallbacksSharedPtr = std::shared_ptr<ActiveStreamCallbacks>;
using ActiveStreamCallbacksWeakPtr = std::weak_ptr<ActiveStreamCallbacks>;

class ActiveStreamInterface {
public:
  ActiveStreamInterface(stream_id_t stream_id, ::Envoy::Event::Dispatcher& source_dispatcher, ActiveStreamCallbacksWeakPtr callbacks);

  absl::Status requestOpenDownstreamChannel(Network::IoHandlePtr io_handle) {
    if (callbacks_.expired()) {
      return absl::CancelledError("stream disconnected");
    }
    auto start = absl::Now();
    std::static_pointer_cast<IoSocket::UserSpace::PassthroughStateImpl>(static_cast<IoSocket::UserSpace::IoHandleImpl*>(io_handle.get())->passthroughState())
      ->notifyOnStateChange(IoSocket::UserSpace::PassthroughStateImpl::State::Initialized,
                            source_dispatcher_,
                            [this, start, io_handle = std::move(io_handle)] mutable {
                              auto diff = absl::Now() - start;
                              ENVOY_LOG_MISC(debug, "waited {} for passthrough state initialization", absl::FormatDuration(diff));
                              if (auto ptr = callbacks_.lock(); ptr) {
                                ptr->requestOpenDownstreamChannel(std::move(io_handle));
                              } else {
                                ENVOY_LOG_MISC(error, "stream disconnected");
                                io_handle->close();
                                return;
                              }
                            });
    return absl::OkStatus();
  }

  stream_id_t streamId() { return stream_id_; }

  void setEndpointForCluster(const std::string& cluster_id) {
    endpoint_for_cluster_ = cluster_id;
  }
  std::string endpointForCluster() const {
    return endpoint_for_cluster_;
  }

private:
  std::string endpoint_for_cluster_;
  stream_id_t stream_id_;
  Thread::ThreadId source_thread_;
  ActiveStreamCallbacksWeakPtr callbacks_;
  ::Envoy::Event::Dispatcher& source_dispatcher_;
};
using ActiveStreamInterfaceSharedPtr = std::shared_ptr<ActiveStreamInterface>;
using ActiveStreamInterfaceWeakPtr = std::weak_ptr<ActiveStreamInterface>;

class ActiveStreamEndpointListener {
public:
  virtual ~ActiveStreamEndpointListener() = default;
  virtual void onClusterEndpointAdded(stream_id_t key) PURE;
  virtual void onClusterEndpointRemoved(stream_id_t key) PURE;
};

class ActiveStreamHandle : public Envoy::Cleanup {
public:
  ActiveStreamHandle(stream_id_t id, std::function<void()> f)
      : Cleanup(std::move(f)), id_(id) {}

  stream_id_t streamId() const { return id_; }

private:
  stream_id_t id_;
};

class ActiveStreamTracker : public Envoy::Singleton::Instance, Logger::Loggable<Logger::Id::filter> {
public:
  static std::shared_ptr<ActiveStreamTracker> fromContext(::Envoy::Server::Configuration::ServerFactoryContext& context);

  std::unique_ptr<ActiveStreamHandle> insert(stream_id_t key, ActiveStreamInterfaceSharedPtr value) {
    Thread::LockGuard lock(mu_);
    ENVOY_LOG_MISC(info, "tracking new ssh stream: id={}", key);
    active_stream_handles_[key] = value;
    return std::make_unique<ActiveStreamHandle>(key, [this, key] {
      erase(key);
    });
  }
  ActiveStreamInterfaceSharedPtr at(stream_id_t key) {
    Thread::LockGuard lock(mu_);
    return active_stream_handles_[key];
  }

  void setStreamIsClusterEndpoint(stream_id_t stream_id, const std::string& cluster_id, bool is_endpoint) {
    auto id = std::string(absl::StripPrefix(cluster_id, "route-"));
    if (is_endpoint) {
      setEndpointForCluster(stream_id, id);
    } else {
      unsetEndpointForCluster(stream_id, id);
    }
  }

  std::unique_ptr<ActiveStreamHandle> onStreamBegin(stream_id_t stream_id, ::Envoy::Event::Dispatcher& source_dispatcher, ActiveStreamCallbacksWeakPtr source_callbacks) {
    ENVOY_LOG(info, "ThreadLocalData::onStreamBegin [id={}]", stream_id);
    return insert(stream_id, std::make_shared<ActiveStreamInterface>(stream_id, source_dispatcher, source_callbacks));
  }
  absl::Status shutdownStream(stream_id_t stream_id) {
    ENVOY_LOG(info, "ThreadLocalData::shutdownStream [id={}]", stream_id);
    if (auto ptr = at(stream_id); ptr != nullptr) {
      return absl::OkStatus();
    }
    return absl::InvalidArgumentError("stream not found");
  }
  void onStreamEnd(stream_id_t stream_id) {
    ENVOY_LOG(info, "ThreadLocalData::onStreamEnd [id={}]", stream_id);
    erase(stream_id);
  }

  void setEndpointForCluster(stream_id_t key, const std::string& cluster_id) {
    Thread::LockGuard lock(mu_);
    setEndpointForClusterLocked(key, cluster_id);
  }

  void unsetEndpointForCluster(stream_id_t key, const std::string& cluster_id) {
    Thread::LockGuard lock(mu_);
    unsetEndpointForClusterLocked(key, cluster_id);
  }

  std::vector<stream_id_t> endpointsForCluster(const std::string& cluster_id) {
    Thread::LockGuard lock(mu_);
    std::vector<stream_id_t> result;
    for (auto id : cluster_endpoints_[cluster_id]) {
      result.push_back(id);
    }
    return result;
  }

  void addEndpointListener(const std::string& cluster_id, std::weak_ptr<ActiveStreamEndpointListener> listener) {
    Thread::LockGuard lock(mu_);
    auto shared = listener.lock();
    ASSERT(!!shared);
    endpoint_listeners_[cluster_id].push_back(listener);
    ENVOY_LOG_MISC(info, "adding new listener for cluster: {}", cluster_id);
    for (auto id : cluster_endpoints_[cluster_id]) {
      shared->onClusterEndpointAdded(id);
    }
  }

  absl::Status requestOpenDownstreamChannel(Network::Address::InstanceConstSharedPtr addr, Network::IoHandlePtr io_handle);

private:
  void erase(stream_id_t key) {
    Thread::LockGuard lock(mu_);
    ENVOY_LOG_MISC(info, "ssh stream ended: id={}", key);
    if (active_stream_handles_.contains(key)) {
      unsetEndpointForClusterLocked(key, active_stream_handles_[key]->endpointForCluster());
      active_stream_handles_.erase(key);
    }
  }

  void setEndpointForClusterLocked(stream_id_t key, const std::string& cluster_id) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    if (!active_stream_handles_.contains(key)) {
      return;
    }
    active_stream_handles_[key]->setEndpointForCluster(cluster_id);
    cluster_endpoints_[cluster_id].insert(key);
    ENVOY_LOG_MISC(info, "setting cluster association: {} => {}", key, cluster_id);

    auto& listeners = endpoint_listeners_[cluster_id];
    ENVOY_LOG_MISC(info, "notifying {} listeners of cluster association update", listeners.size());
    for (auto&& it = listeners.begin(); it != listeners.end();) {
      auto shared = it->lock();
      if (!shared) {
        ENVOY_LOG_MISC(info, "clearing expired listener for cluster {}", cluster_id);
        it = listeners.erase(it);
      } else {
        shared->onClusterEndpointAdded(key);
        it++;
      }
    }
  }

  void unsetEndpointForClusterLocked(stream_id_t key, const std::string& cluster_id) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    if (cluster_endpoints_[cluster_id].erase(key) == 0) {
      return;
    }
    ENVOY_LOG_MISC(info, "removing cluster association: {} => {}", key, cluster_id);
    if (!active_stream_handles_.contains(key)) {
      return;
    }
    active_stream_handles_[key]->setEndpointForCluster("");
    auto& listeners = endpoint_listeners_[cluster_id];
    ENVOY_LOG_MISC(info, "notifying {} listeners of cluster association update", listeners.size());
    for (auto&& it = listeners.begin(); it != listeners.end();) {
      auto shared = it->lock();
      if (!shared) {
        it = listeners.erase(it);
      } else {
        shared->onClusterEndpointRemoved(key);
        it++;
      }
    }
  }

  Thread::MutexBasicLockable mu_;
  absl::node_hash_map<stream_id_t, ActiveStreamInterfaceSharedPtr> ABSL_GUARDED_BY(mu_) active_stream_handles_;

  std::unordered_map<std::string, std::unordered_set<stream_id_t>> ABSL_GUARDED_BY(mu_) cluster_endpoints_;
  std::unordered_map<std::string, std::list<std::weak_ptr<ActiveStreamEndpointListener>>> ABSL_GUARDED_BY(mu_) endpoint_listeners_;
};

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec
