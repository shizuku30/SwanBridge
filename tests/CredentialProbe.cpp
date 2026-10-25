#include <windows.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Core.h>
#include <winrt/Windows.Security.Cryptography.DataProtection.h>
#include <winrt/Windows.Storage.Streams.h>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace winrt;
using namespace Windows::Security::Cryptography;
using namespace Windows::Security::Cryptography::Core;
using namespace Windows::Security::Cryptography::DataProtection;
using namespace Windows::Storage::Streams;

void Check(bool condition, char const* description)
{
    if (!condition) throw std::runtime_error(description);
    std::cout << "PASS " << description << '\n';
}

int wmain(int argc, wchar_t** argv)
{
    try
    {
        init_apartment();
        if (argc == 3 && std::wstring_view(argv[1]) == L"--protect-stdin")
        {
            std::string secret;
            if (!std::getline(std::cin, secret) || secret.empty() || secret.size() > 1024)
                throw std::runtime_error("A nonempty credential of at most 1024 bytes is required on stdin");
            const auto input = CryptographicBuffer::CreateFromByteArray(array_view<std::uint8_t const>(
                reinterpret_cast<std::uint8_t const*>(secret.data()),
                reinterpret_cast<std::uint8_t const*>(secret.data() + secret.size())));
            const auto protectedKey = DataProtectionProvider(L"LOCAL=user").ProtectAsync(input).get();
            SecureZeroMemory(secret.data(), secret.size());
            com_array<std::uint8_t> bytes;
            CryptographicBuffer::CopyToByteArray(protectedKey, bytes);
            std::ofstream output(std::filesystem::path(argv[2]), std::ios::binary | std::ios::trunc);
            output.write(reinterpret_cast<char const*>(bytes.data()), bytes.size());
            if (!output) throw std::runtime_error("Cannot write protected credential");
            std::cout << "PASS credential protected for the current user; plaintext was not written\n";
            return 0;
        }
        if (argc != 1 && argc != 3)
        {
            std::cerr << "Usage: CredentialProbe.exe [protected-file expected-sha256]\n";
            return 2;
        }

        IBuffer encrypted{ nullptr };
        hstring expectedHash;
        std::vector<std::uint8_t> fileBytes;
        if (argc == 3)
        {
            std::ifstream file(std::filesystem::path(argv[1]), std::ios::binary);
            if (!file) throw std::runtime_error("Cannot read protected credential file");
            fileBytes.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
            encrypted = CryptographicBuffer::CreateFromByteArray(fileBytes);
            expectedHash = argv[2];
        }
        else
        {
            const auto fixture = CryptographicBuffer::GenerateRandom(32);
            expectedHash = CryptographicBuffer::EncodeToHexString(
                HashAlgorithmProvider::OpenAlgorithm(L"SHA256").HashData(fixture));
            encrypted = DataProtectionProvider(L"LOCAL=user").ProtectAsync(fixture).get();
            com_array<std::uint8_t> encryptedBytes;
            CryptographicBuffer::CopyToByteArray(encrypted, encryptedBytes);
            fileBytes.assign(encryptedBytes.begin(), encryptedBytes.end());
        }

        const auto clear = DataProtectionProvider().UnprotectAsync(encrypted).get();
        const auto actualHash = CryptographicBuffer::EncodeToHexString(
            HashAlgorithmProvider::OpenAlgorithm(L"SHA256").HashData(clear));
        Check(_wcsicmp(actualHash.c_str(), expectedHash.c_str()) == 0,
            "protected credential decrypts to the expected SHA256");

        com_array<std::uint8_t> clearBytes;
        CryptographicBuffer::CopyToByteArray(clear, clearBytes);
        const bool absent = !clearBytes.empty() && std::search(fileBytes.begin(), fileBytes.end(),
            clearBytes.begin(), clearBytes.end()) == fileBytes.end();
        SecureZeroMemory(clearBytes.data(), clearBytes.size());
        Check(absent, "protected blob does not contain plaintext credential");
        return 0;
    }
    catch (hresult_error const& error)
    {
        std::cerr << "FAIL credential protection HRESULT 0x" << std::hex
            << static_cast<unsigned>(error.code()) << '\n';
        return 1;
    }
    catch (std::exception const& error)
    {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
