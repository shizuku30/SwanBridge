#pragma once
#include <cstdint>

namespace swanbridge
{
    constexpr bool SystemPaletteIsDark(std::uint8_t foregroundRed, std::uint8_t foregroundGreen, std::uint8_t foregroundBlue)
    {
        return 2 * foregroundRed + 5 * foregroundGreen + foregroundBlue > 8 * 128;
    }
}
