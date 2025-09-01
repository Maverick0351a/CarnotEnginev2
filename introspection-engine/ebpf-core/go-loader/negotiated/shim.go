package negotiated

/*
#cgo LDFLAGS: -lssl -lcrypto -ldl
#include <stdlib.h>
#include <dlfcn.h>
#include <openssl/ssl.h>

const SSL_CIPHER* get_current_cipher(void* p) {
    return SSL_get_current_cipher((SSL*)p);
}
const char* cipher_name(const SSL_CIPHER* c) {
    if (!c) return NULL;
    return SSL_CIPHER_get_name(c);
}
unsigned int call_ssl_get_negotiated_group(void* p) {
    void* h = dlopen("libssl.so.3", RTLD_LAZY);
    if (!h) h = dlopen("libssl.so.1.1", RTLD_LAZY);
    if (!h) return 0;
    typedef unsigned int (*fn_t)(void*);
    fn_t f = (fn_t)dlsym(h, "SSL_get_negotiated_group");
    unsigned int id = 0;
    if (f) {
        id = f(p);
    }
    dlclose(h);
    return id;
}
int get_shared_group0(void* p) {
    return SSL_get_shared_group((SSL*)p, 0);
}
*/
import "C"
import (
    "fmt"
    "unsafe"
)

func GetCipherName(sslPtr uintptr) (string, error) {
    c := C.get_current_cipher(unsafe.Pointer(sslPtr))
    if c == nil {
        return "", fmt.Errorf("no current cipher")
    }
    name := C.cipher_name(c)
    if name == nil {
        return "", fmt.Errorf("no cipher name")
    }
    return C.GoString(name), nil
}

func mapGroup(id int) string {
    switch id {
    case 23:
        return "secp256r1"
    case 24:
        return "secp384r1"
    case 29:
        return "x25519"
    case 30:
        return "x448"
    default:
        return ""
    }
}

// GetGroupSelected attempts to retrieve the negotiated group using the best available method.
// Returns (groupName, source)
func GetGroupSelected(sslPtr uintptr) (string, string) {
    if sslPtr == 0 {
        return "", "unknown"
    }
    // Prefer SSL_get_negotiated_group if available at runtime
    id := int(C.call_ssl_get_negotiated_group(unsafe.Pointer(sslPtr)))
    if id > 0 {
        if name := mapGroup(id); name != "" {
            return name, "ssl_get_negotiated_group"
        }
        // fallthrough to shared_group mapping if unknown id
    }
    // Fallback to SSL_get_shared_group(…, 0)
    id2 := int(C.get_shared_group0(unsafe.Pointer(sslPtr)))
    if id2 > 0 {
        if name := mapGroup(id2); name != "" {
            return name, "ssl_get_shared_group"
        }
    }
    return "", "unknown"
}
