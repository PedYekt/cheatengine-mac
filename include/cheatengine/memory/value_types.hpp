#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace cheatengine {

enum class ValueType { INT32, INT64, FLOAT32, FLOAT64, BYTES };

class SearchValue {
public:
    ValueType type() const { return type_; }
    const std::vector<std::uint8_t>& data() const { return data_; }

    static SearchValue fromInt32(std::int32_t value);
    static SearchValue fromInt64(std::int64_t value);
    static SearchValue fromFloat32(float value);
    static SearchValue fromFloat64(double value);
    static SearchValue fromBytes(const std::vector<std::uint8_t>& bytes);

    std::int32_t toInt32() const;
    std::int64_t toInt64() const;
    float toFloat32() const;
    double toFloat64() const;

private:
    template <typename T>
    static std::vector<std::uint8_t> toBytes(const T& value) {
        std::vector<std::uint8_t> bytes(sizeof(T));
        std::memcpy(bytes.data(), &value, sizeof(T));
        return bytes;
    }

    ValueType type_{ValueType::BYTES};
    std::vector<std::uint8_t> data_;
};

} // namespace cheatengine
