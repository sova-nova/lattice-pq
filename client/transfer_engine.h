#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "key_store.h"
#include "platform.h"

// Runs one upload or download at a time on the calling (worker) thread and
// reports progress through the callbacks. Never throws: every failure is
// reported through on_error.
class TransferEngine {
public:
    TransferEngine() = default;

    // The relay's ID to insist on for the next transfers (empty: accept any relay, and remember what it was: see relay_seen).
    void set_trusted_relay(const std::vector<uint8_t>& relay_id) {
        std::lock_guard<std::mutex> lock(relay_mutex_);
        trusted_relay_ = relay_id;
    }
    // The ID of the relay the last connection was encrypted with (empty if none got that far).
    std::vector<uint8_t> relay_seen() const {
        std::lock_guard<std::mutex> lock(relay_mutex_);
        return relay_seen_;
    }

    // Encrypts `filepath` (UTF-8) for `recipient`, signs it with this user's
    // ML-DSA key and uploads it to the relay.
    void upload_file(const std::string& filepath,
                     const std::string& server_host,
                     uint16_t server_port,
                     const KeyStore::Contact& recipient);

    // Several files, or a folder, sent as one: packed into one file (file_pack, a plain tar archive) in a folder of its
    // own under `work_dir`, which is uploaded like upload_file and deleted afterwards, whatever happened. One plain file
    // is sent as itself. A snapshot: the files are read once, while packing; cancel() stops the packing too.
    void upload_files(const std::vector<std::string>& sources,
                      const std::string& server_host,
                      uint16_t server_port,
                      const KeyStore::Contact& recipient,
                      const std::string& work_dir);

    // Downloads a transfer, verifies the sender against the contact list,
    // decrypts it into `output_dir` (UTF-8), then tells the relay to delete it.
    // Files sent together (a pack, by its name) are then unpacked into a folder there and the archive removed; if that
    // fails or is cancelled, the archive is kept and on_error says where (on_complete is not called then).
    void download_file(const std::string& transfer_id,
                       const std::string& server_host,
                       uint16_t server_port,
                       const std::string& output_dir);

    // Thread-safe. Aborts the running transfer promptly (closes its socket).
    void cancel();

    // The key store to take this user's keys from. Must outlive any running transfer. Needed
    // when the private keys are protected by a passphrase, because only the app's key store
    // holds them unlocked. Without it, each transfer opens the key files itself.
    void set_keystore(const KeyStore* keystore) { keystore_ = keystore; }

    std::function<void(double fraction)> on_progress;
    std::function<void(const std::string& msg)> on_status;
    std::function<void(const std::string& error)> on_error;
    std::function<void(const std::string& filepath)> on_complete;
    std::function<void(const std::string& transfer_id)> on_transfer_id;

private:
    mutable std::mutex relay_mutex_;
    std::vector<uint8_t> trusted_relay_, relay_seen_;
    const KeyStore* keystore_ = nullptr;
    const KeyStore& active_keystore(std::unique_ptr<KeyStore>& fallback) const;

    std::atomic<bool> cancel_flag_{false};
    std::mutex socket_mutex_;
    socket_t active_socket_ = INVALID_SOCKET_VAL;

    void upload_impl(const std::string& filepath, const std::string& host, uint16_t port,
                     const KeyStore::Contact& recipient);
    std::filesystem::path download_impl(const std::string& transfer_id, const std::string& host, uint16_t port,
                                        const std::string& output_dir, bool& is_pack);
    std::filesystem::path pack_impl(const std::vector<std::string>& sources, const std::filesystem::path& job_dir);
    void unpack_impl(const std::filesystem::path& archive, const std::string& output_dir);

    socket_t connect_to_server(const std::string& host, uint16_t port);
    void release_socket(socket_t sock);
    void check_cancelled() const;

    void status(const std::string& msg);
    void progress(double fraction);
};
