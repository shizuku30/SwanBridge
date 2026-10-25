#pragma once
#include <string>
#include <vector>

namespace swanbridge
{
    struct ProfileEditorState
    {
        std::vector<std::wstring> fields;
        bool excludeLocalSubnets = true;
        bool operator==(ProfileEditorState const&) const = default;
    };

    inline bool HasEditorChanges(ProfileEditorState const& current, ProfileEditorState const& saved, bool hasNewPsk)
    {
        return hasNewPsk || current != saved;
    }
}
