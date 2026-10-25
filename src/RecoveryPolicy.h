#pragma once
#include <cstdint>

namespace swanbridge
{
    inline bool AcceptanceDropActive(std::int64_t now, std::int64_t leaseExpires, std::int64_t dropUntil)
    {
        return now >= 0 && leaseExpires > now && leaseExpires - now <= 4 * 60 * 60 * 1000LL &&
            dropUntil > now && dropUntil <= leaseExpires && dropUntil - now <= 120000;
    }
}
