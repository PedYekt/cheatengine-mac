#include "cheatengine/memory/value_types.hpp"
#include <stdexcept>

namespace cheatengine {

SearchValue SearchValue::fromInt32(std::int32_t value)
{
    SearchValue sv;
    sv.type_ = ValueType::INT32;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromInt64(std::int64_t value)
{
    SearchValue sv;
    sv.type_ = ValueType::INT64;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromFloat32(float value)
{
    SearchValue sv;
    sv.type_ = ValueType::FLOAT32;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromFloat64(double value)
{
    SearchValue sv;
    sv.type_ = ValueType::FLOAT64;
    sv.data_ = toBytes(value);
    return sv;
}

SearchValue SearchValue::fromBytes(const std::vector<std::uint8_t>& bytes)
{
    SearchValue sv;
    sv.type_ = ValueType::BYTES;
    sv.data_ = bytes;
    return sv;
}

std::int32_t SearchValue::toInt32() const
{
    if (type_ != ValueType::INT32 || data_.size() != sizeof(std::int32_t)) {
        throw std::runtime_error("SearchValue is not an INT32 type or has invalid size");
    }
    std::int32_t value;
    std::memcpy(&value, data_.data(), sizeof(std::int32_t));
    return value;
}

std::int64_t SearchValue::toInt64() const
{
    if (type_ != ValueType::INT64 || data_.size() != sizeof(std::int64_t)) {
        throw std::runtime_error("SearchValue is not an INT64 type or has invalid size");
    }
    std::int64_t value;
    std::memcpy(&value, data_.data(), sizeof(std::int64_t));
    return value;
}

float SearchValue::toFloat32() const
{
    if (type_ != ValueType::FLOAT32 || data_.size() != sizeof(float)) {
        throw std::runtime_error("SearchValue is not a FLOAT32 type or has invalid size");
    }
    float value;
    std::memcpy(&value, data_.data(), sizeof(float));
    return value;
}

double SearchValue::toFloat64() const
{
    if (type_ != ValueType::FLOAT64 || data_.size() != sizeof(double)) {
        throw std::runtime_error("SearchValue is not a FLOAT64 type or has invalid size");
    }
    double value;
    std::memcpy(&value, data_.data(), sizeof(double));
    return value;
}

} // namespace cheatengine
