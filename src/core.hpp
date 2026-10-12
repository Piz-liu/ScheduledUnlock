#pragma once
#include <stdint.h>

namespace su {
constexpr uint64_t kTicksPerSecond = 10000000;
constexpr uint64_t kRequestLifetime = 90 * kTicksPerSecond;
constexpr uint32_t kInvalidSession = 0xffffffffu;

// A request is scoped to one console session and one configuration revision.
struct Request {
    uint32_t version = 1;
    uint32_t session = kInvalidSession;
    uint64_t generation = 0;
    uint64_t nonce = 0;
    uint64_t issued = 0;
    uint64_t expires = 0;
};
static_assert(sizeof(Request) == 40, "Stable registry wire format");

inline bool Eligible(const Request& r, uint64_t now,
                     uint32_t session, uint64_t generation,
                     bool locked) noexcept {
    return locked && session != kInvalidSession && r.version == 1 &&
        generation != 0 && r.generation == generation && r.session == session &&
        r.nonce != 0 && r.issued != 0 && r.expires > r.issued &&
        r.expires - r.issued <= kRequestLifetime &&
        now >= r.issued && now < r.expires;
}
}
