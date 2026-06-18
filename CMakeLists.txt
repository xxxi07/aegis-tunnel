cmake_minimum_required(VERSION 3.16)
project(aegis-tunnel VERSION 0.1.0 LANGUAGES C)

# ── C Standard ──
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Options ──
option(BUILD_TESTS    "Build test programs" ON)
option(BUILD_BENCH    "Build benchmark" ON)
option(ENABLE_ASAN    "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN   "Enable UndefinedBehaviorSanitizer" OFF)
option(WITH_NEON      "Enable ARM NEON optimization" ON)

# ── Check for explicit_bzero ──
include(CheckSymbolExists)
check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)
if(HAVE_EXPLICIT_BZERO)
    add_compile_definitions(HAVE_EXPLICIT_BZERO=1)
endif()

# ── OpenSSL (for SHA256 key derivation + ECDH) ──
find_package(OpenSSL REQUIRED)

# ── Sanitizers ──
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()
if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

# ── Feature test macros ──
add_compile_definitions(_GNU_SOURCE)

# ── Common compile options ──
add_compile_options(-Wall -Wextra -Wpedantic
                    -Wshadow -Wconversion -Wstrict-prototypes
                    -Wmissing-prototypes)

# Relax some warnings for C99 compatibility
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wno-declaration-after-statement)
endif()

# ════════════════════════════════════════════════════════════════
# Source files (organized by module)
# ════════════════════════════════════════════════════════════════

set(CRYPTO_SOURCES
    src/crypto/aegis.c
)

set(PROTOCOL_SOURCES
    src/protocol/handshake.c
    src/protocol/ecdh.c
    src/protocol/frame_reader.c
)

set(TUNNEL_SOURCES
    src/tunnel/tunnel.c
    src/tunnel/tun.c
)

set(PROXY_SOURCES
    src/proxy/socks5.c
)

set(UTIL_SOURCES
    src/util/util.c
)

# Library sources (reusable as .so/.a)
set(LIB_SOURCES
    ${CRYPTO_SOURCES}
    ${PROTOCOL_SOURCES}
    ${TUNNEL_SOURCES}
    ${PROXY_SOURCES}
    ${UTIL_SOURCES}
)

# Main executable (adds main.c on top of library)
set(MAIN_SOURCES
    src/main.c
    src/mode_psk.c
    src/mode_tun.c
    src/mode_socks5.c
    src/config_mgmt.c
    src/mode_common.c
    ${LIB_SOURCES}
)

# ════════════════════════════════════════════════════════════════
# NEON static library (ARM aarch64 only)
# ════════════════════════════════════════════════════════════════

set(NEON_LIB "")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64" AND WITH_NEON)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-march=armv8-a")
    check_c_source_compiles("
        #include <arm_neon.h>
        int main(void) {
            uint8x16_t v = vdupq_n_u8(0);
            (void)v;
            return 0;
        }
    " AEGIS_HAVE_NEON)

    if(AEGIS_HAVE_NEON)
        # Plain NEON (tbl/tbx) — works on all ARMv8 CPUs
        add_library(aegis128-neon STATIC
            src/crypto/neon/aegis128-plain.c
        )
        target_compile_options(aegis128-neon PRIVATE
            -O3 -march=armv8-a -mtune=native
        )
        target_compile_definitions(aegis128-neon PRIVATE
            AEGIS_HAVE_NEON=1
        )
        target_include_directories(aegis128-neon PUBLIC
            ${CMAKE_SOURCE_DIR}/src
        )
        set(NEON_LIB aegis128-neon)
        message(STATUS "NEON optimization: ENABLED")

        # ARM Crypto (aese/aesmc) — requires ARMv8-AES
        set(CMAKE_REQUIRED_FLAGS "-march=armv8-a+crypto")
        check_c_source_compiles("
            #include <arm_neon.h>
            int main(void) {
                uint8x16_t v = vdupq_n_u8(0);
                v = vaesmcq_u8(vaeseq_u8(v, v));
                (void)v;
                return 0;
            }
        " AEGIS_HAVE_ARMCRYPTO)

        if(AEGIS_HAVE_ARMCRYPTO)
            add_library(aegis128-armcrypto STATIC
                src/crypto/neon/aegis128-armcrypto.c
            )
            target_compile_options(aegis128-armcrypto PRIVATE
                -O3 -march=armv8-a+crypto -mtune=native
            )
            target_compile_definitions(aegis128-armcrypto PRIVATE
                AEGIS_HAVE_ARMCRYPTO=1
            )
            target_include_directories(aegis128-armcrypto PUBLIC
                ${CMAKE_SOURCE_DIR}/src
            )
            list(APPEND NEON_LIB aegis128-armcrypto)
            message(STATUS "ARM Crypto (AES): ENABLED")
        else()
            message(STATUS "ARM Crypto (AES): not available on this ARM target")
        endif()
    else()
        message(STATUS "NEON optimization: ARM target but NEON compile check failed")
    endif()
else()
    message(STATUS "NEON optimization: not available (${CMAKE_SYSTEM_PROCESSOR})")
endif()

# ════════════════════════════════════════════════════════════════
# x86 AES-NI optimization (x86_64 with -maes)
# ════════════════════════════════════════════════════════════════

set(AESNI_LIB "")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-maes -msse2")
    check_c_source_compiles("
        #include <wmmintrin.h>
        #include <emmintrin.h>
        int main(void) {
            __m128i v = _mm_setzero_si128();
            v = _mm_aesenc_si128(v, v);
            (void)v;
            return 0;
        }
    " AEGIS_HAVE_AESNI)

    if(AEGIS_HAVE_AESNI)
        add_library(aegis128-x86 STATIC
            src/crypto/x86/aegis128-x86.c
        )
        target_compile_options(aegis128-x86 PRIVATE
            -O3 -maes -msse2 -mtune=native
        )
        target_compile_definitions(aegis128-x86 PRIVATE
            AEGIS_HAVE_AESNI=1
        )
        target_include_directories(aegis128-x86 PUBLIC
            ${CMAKE_SOURCE_DIR}/src
        )
        set(AESNI_LIB aegis128-x86)
        list(APPEND CRYPTO_SOURCES src/crypto/x86/aegis128-x86.c)
        message(STATUS "x86 AES-NI optimization: ENABLED")
    else()
        message(STATUS "x86 AES-NI: x86_64 target but AES-NI compile check failed")
    endif()
else()
    message(STATUS "x86 AES-NI: not available (${CMAKE_SYSTEM_PROCESSOR})")
endif()

# ════════════════════════════════════════════════════════════════
# Build targets
# ════════════════════════════════════════════════════════════════

# Shared library
add_library(aegis-tunnel-lib SHARED ${LIB_SOURCES})
target_include_directories(aegis-tunnel-lib PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(aegis-tunnel-lib PRIVATE ${NEON_LIB} ${AESNI_LIB} OpenSSL::Crypto)
set_target_properties(aegis-tunnel-lib PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)
if(NEON_LIB)
    target_compile_definitions(aegis-tunnel-lib PRIVATE AEGIS_HAVE_NEON=1)
endif()

# Static library
add_library(aegis-tunnel-static STATIC ${LIB_SOURCES})
target_include_directories(aegis-tunnel-static PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(aegis-tunnel-static PRIVATE ${NEON_LIB} ${AESNI_LIB} OpenSSL::Crypto)
if(NEON_LIB)
    target_compile_definitions(aegis-tunnel-static PRIVATE AEGIS_HAVE_NEON=1)
endif()

# Main executable
add_executable(aegis-tunnel ${MAIN_SOURCES})
target_include_directories(aegis-tunnel PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(aegis-tunnel PRIVATE ${NEON_LIB} ${AESNI_LIB} OpenSSL::Crypto)
if(NEON_LIB)
    target_compile_definitions(aegis-tunnel PRIVATE AEGIS_HAVE_NEON=1)
endif()

# ════════════════════════════════════════════════════════════════
# Tests
# ════════════════════════════════════════════════════════════════

if(BUILD_TESTS)
    add_executable(test-aegis
        tests/test_aegis.c
        ${CRYPTO_SOURCES}
        ${UTIL_SOURCES}
    )
    target_include_directories(test-aegis PRIVATE ${CMAKE_SOURCE_DIR}/src)
    if(NEON_LIB)
        target_link_libraries(test-aegis PRIVATE ${NEON_LIB})
        target_compile_definitions(test-aegis PRIVATE AEGIS_HAVE_NEON=1)
    endif()

    add_executable(test-tunnel
        tests/test_tunnel.c
        ${PROTOCOL_SOURCES}
        ${TUNNEL_SOURCES}
        ${CRYPTO_SOURCES}
        ${UTIL_SOURCES}
    )
    target_include_directories(test-tunnel PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(test-tunnel PRIVATE ${NEON_LIB} OpenSSL::Crypto pthread)
    if(NEON_LIB)
        target_compile_definitions(test-tunnel PRIVATE AEGIS_HAVE_NEON=1)
    endif()
endif()

# ════════════════════════════════════════════════════════════════
# Benchmark
# ════════════════════════════════════════════════════════════════

if(BUILD_BENCH)
    add_executable(bench-aegis
        tests/bench_aegis.c
        ${CRYPTO_SOURCES}
        ${UTIL_SOURCES}
    )
    target_include_directories(bench-aegis PRIVATE ${CMAKE_SOURCE_DIR}/src)
    if(NEON_LIB)
        target_link_libraries(bench-aegis PRIVATE ${NEON_LIB})
        target_compile_definitions(bench-aegis PRIVATE AEGIS_HAVE_NEON=1)
    endif()
endif()
