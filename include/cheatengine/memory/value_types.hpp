/**
 * @file value_types.hpp
 * @brief Type-safe value representation for memory searching
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

namespace cheatengine {

/**
 * @brief Supported value types for memory searching
 */
enum class ValueType {
    INT32,      ///< 32-bit signed integer (4 bytes)
    INT64,      ///< 64-bit signed integer (8 bytes)  
    FLOAT32,    ///< 32-bit IEEE 754 floating point (4 bytes)
    FLOAT64,    ///< 64-bit IEEE 754 floating point (8 bytes)
    BYTES       ///< Raw byte sequence (variable length)
};

/**
 * @brief Type-safe container for values to search in memory
 */
class SearchValue {
public:
    /**
     * @brief Get the type of value stored
     * @return ValueType The type category of this value
     */
    ValueType type() const noexcept { return type_; }
    
    /**
     * @brief Get the raw binary data
     * @return const std::vector<std::uint8_t>& Binary representation of the value
     */
    const std::vector<std::uint8_t>& data() const noexcept { return data_; }

    // Factory methods for creating SearchValues.
    
    /**
     * @brief Create SearchValue from 32-bit signed integer
     * @param value Integer value to store
     * @return SearchValue Type-safe container for the integer
     */
    static SearchValue fromInt32(std::int32_t value);
    
    /**
     * @brief Create SearchValue from 64-bit signed integer
     * @param value Integer value to store
     * @return SearchValue Type-safe container for the integer
     */
    static SearchValue fromInt64(std::int64_t value);
    
    /**
     * @brief Create SearchValue from 32-bit floating point
     * @param value Float value to store
     * @return SearchValue Type-safe container for the float
     */
    static SearchValue fromFloat32(float value);
    
    /**
     * @brief Create SearchValue from 64-bit floating point
     * @param value Double value to store
     * @return SearchValue Type-safe container for the double
     */
    static SearchValue fromFloat64(double value);
    
    /**
     * @brief Create SearchValue from raw byte sequence
     * @param bytes Raw binary data to store
     * @return SearchValue Type-safe container for the bytes
     */
    static SearchValue fromBytes(const std::vector<std::uint8_t>& bytes);

    // Conversion utilities for extracting values from SearchValue.
    
    /**
     * @brief Extract value as 32-bit signed integer
     * @return std::int32_t The stored integer value
     */
    std::int32_t toInt32() const;
    
    /**
     * @brief Extract value as 64-bit signed integer
     * @return std::int64_t The stored integer value
     */
    std::int64_t toInt64() const;
    
    /**
     * @brief Extract value as 32-bit floating point
     * @return float The stored float value
     */
    float toFloat32() const;
    
    /**
     * @brief Extract value as 64-bit floating point
     * @return double The stored double value
     */
    double toFloat64() const;
    
    /**
     * @brief Template-based value extraction with compile-time type checking
     * @return T The stored value converted to requested type
     */
    template <typename T>
    T getValue() const
    {
        if constexpr (std::is_same_v<T, std::int32_t>) {
            return toInt32();
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            return toInt64();
        } else if constexpr (std::is_same_v<T, float>) {
            return toFloat32();
        } else if constexpr (std::is_same_v<T, double>) {
            return toFloat64();
        } else {
            static_assert(always_false<T>::value, "Unsupported type for SearchValue::getValue");
        }
    }

    /**
     * @brief Template factory method for creating SearchValues from any supported type
     * @param value Value to store in the SearchValue
     * @return SearchValue Type-safe container for the value
     */
    template <typename T>
    static SearchValue create(T value)
    {
        if constexpr (std::is_integral_v<T>) {
            if constexpr (sizeof(T) == sizeof(std::int32_t)) {
                return fromInt32(static_cast<std::int32_t>(value));
            } else if constexpr (sizeof(T) == sizeof(std::int64_t)) {
                return fromInt64(static_cast<std::int64_t>(value));
            } else {
                static_assert(always_false<T>::value, "Unsupported integral size for SearchValue::create");
            }
        } else if constexpr (std::is_floating_point_v<T>) {
            if constexpr (sizeof(T) == sizeof(float)) {
                return fromFloat32(static_cast<float>(value));
            } else if constexpr (sizeof(T) == sizeof(double)) {
                return fromFloat64(static_cast<double>(value));
            } else {
                static_assert(always_false<T>::value, "Unsupported floating-point size for SearchValue::create");
            }
        } else {
            static_assert(always_false<T>::value, "Unsupported type for SearchValue::create");
        }
    }

private:
    /**
     * @brief Helper template for static_assert in template contexts
     */
    template <typename>
    struct always_false : std::false_type {
    };

    /**
     * @brief Convert typed value to binary representation
     * @param value Value to convert to bytes
     * @return std::vector<std::uint8_t> Binary representation of the value
     */
    template <typename T>
    static std::vector<std::uint8_t> toBytes(const T& value)
    {
        std::vector<std::uint8_t> bytes(sizeof(T));
        std::memcpy(bytes.data(), &value, sizeof(T));
        return bytes;
    }

    ValueType type_{ValueType::BYTES};          ///< Type category of stored value
    std::vector<std::uint8_t> data_;           ///< Binary representation of the value
};

} // namespace cheatengine
