//go:build darwin && cgo

package nativedns

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <TargetConditionals.h>
#include <stdbool.h>

static CFArrayRef amneziaLocalTrustCertificates(void) {
#if TARGET_OS_OSX
	CFArrayRef anchors = NULL;
	if (SecTrustCopyAnchorCertificates(&anchors) != errSecSuccess || !anchors) {
		if (anchors) CFRelease(anchors);
		return NULL;
	}
	CFMutableArrayRef all = CFArrayCreateMutableCopy(NULL, 0, anchors);
	CFRelease(anchors);
	if (!all) return NULL;
	const SecTrustSettingsDomain domains[] = {
		kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin, kSecTrustSettingsDomainSystem
	};
	for (unsigned i = 0; i < sizeof(domains)/sizeof(domains[0]); ++i) {
		CFArrayRef certificates = NULL;
		OSStatus status = SecTrustSettingsCopyCertificates(domains[i], &certificates);
		if (status == errSecNoTrustSettings) {
			if (certificates) CFRelease(certificates);
			continue;
		}
		if (status != errSecSuccess || !certificates) {
			if (certificates) CFRelease(certificates);
			CFRelease(all);
			return NULL;
		}
		CFArrayAppendArray(all, certificates, CFRangeMake(0, CFArrayGetCount(certificates)));
		CFRelease(certificates);
	}
	return all;
#else
	// iOS does not expose the macOS trust-anchor/settings enumeration contract.
	// Do not substitute bundled roots or enable online platform verification.
	return NULL;
#endif
}

static CFDataRef amneziaCertificateData(CFArrayRef certificates, CFIndex index) {
	CFTypeRef certificate = CFArrayGetValueAtIndex(certificates, index);
	if (!certificate || CFGetTypeID(certificate) != SecCertificateGetTypeID()) return NULL;
	return SecCertificateCopyData((SecCertificateRef)certificate);
}

static int amneziaAppendCertificate(CFMutableArrayRef certificates, const void *bytes, CFIndex length) {
	CFDataRef data = CFDataCreate(NULL, bytes, length);
	if (!data) return 0;
	SecCertificateRef certificate = SecCertificateCreateWithData(NULL, data);
	CFRelease(data);
	if (!certificate) return 0;
	CFArrayAppendValue(certificates, certificate);
	CFRelease(certificate);
	return 1;
}

static int amneziaAppendData(CFMutableArrayRef array, const void *bytes, CFIndex length) {
	CFDataRef data = CFDataCreate(NULL, bytes, length);
	if (!data) return 0;
	CFArrayAppendValue(array, data);
	CFRelease(data);
	return 1;
}

// Read-only, certificate-specific ownership check. An empty settings array is
// still an explicit trust grant, NOT absence. No trust settings are modified.
static int amneziaCertificateTrustAbsent(const void *bytes, CFIndex length) {
#if TARGET_OS_OSX
	CFDataRef data = CFDataCreate(NULL, bytes, length);
	if (!data) return -1;
	SecCertificateRef certificate = SecCertificateCreateWithData(NULL, data);
	CFRelease(data);
	if (!certificate) return -1;
	const SecTrustSettingsDomain domains[] = {kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin};
	int absent = 1;
	for (unsigned i = 0; i < sizeof(domains)/sizeof(domains[0]); ++i) {
		CFArrayRef settings = NULL;
		OSStatus status = SecTrustSettingsCopyTrustSettings(certificate, domains[i], &settings);
		if (settings) CFRelease(settings);
		if (status != errSecItemNotFound) {
			absent = status == errSecSuccess ? 0 : (status < 0 ? (int)status : -1);
			break;
		}
	}
	CFRelease(certificate);
	return absent;
#else
	return -1;
#endif
}

static int amneziaVerifyCachedSSL(CFArrayRef certificates, const char *name,
		CFDataRef ocsp, CFArrayRef timestamps) {
	CFStringRef hostname = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
	if (!hostname) return 0;
	SecPolicyRef ssl = SecPolicyCreateSSL(true, hostname);
	CFRelease(hostname);
	// Preserve native revocation checks while forbidding their implicit network
	// transport as well as missing-intermediate retrieval.
	SecPolicyRef revocation = SecPolicyCreateRevocation(
		kSecRevocationUseAnyAvailableMethod | kSecRevocationNetworkAccessDisabled);
	if (!ssl || !revocation) {
		if (ssl) CFRelease(ssl);
		if (revocation) CFRelease(revocation);
		return 0;
	}
	const void *values[] = {ssl, revocation};
	CFArrayRef policies = CFArrayCreate(NULL, values, 2, &kCFTypeArrayCallBacks);
	CFRelease(ssl);
	CFRelease(revocation);
	if (!policies) return 0;
	SecTrustRef trust = NULL;
	OSStatus status = SecTrustCreateWithCertificates(certificates, policies, &trust);
	CFRelease(policies);
	if (status != errSecSuccess || !trust) {
		if (trust) CFRelease(trust);
		return 0;
	}
	int accepted = 0;
	if (SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess
			&& (!ocsp || SecTrustSetOCSPResponse(trust, ocsp) == errSecSuccess)
			&& (!timestamps || SecTrustSetSignedCertificateTimestamps(trust, timestamps) == errSecSuccess)) {
		CFErrorRef error = NULL;
		accepted = SecTrustEvaluateWithError(trust, &error);
		if (error) CFRelease(error);
	}
	CFRelease(trust);
	return accepted;
}
*/
import "C"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"runtime"
	"strings"
	"unsafe"
)

// Keep normal Go TLS CA/signature/name verification enabled with original local
// trust candidates, AND require native SSL/trust settings. Enumeration is not a
// trust decision: user/admin deny and usage constraints remain native decisions.
func scopedTLSConfig(config *tls.Config) (*tls.Config, error) {
	if config == nil || config.InsecureSkipVerify || config.ServerName == "" ||
		strings.ContainsAny(config.ServerName, "\x00\r\n") {
		return nil, ErrScopeUnavailable
	}
	if config.RootCAs != nil {
		return config, nil // Original explicit closed test policy.
	}
	roots, err := darwinRootSnapshot()
	if err != nil {
		return nil, err
	}
	selected := config.Clone()
	selected.RootCAs = roots
	previous := selected.VerifyConnection
	selected.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || len(state.PeerCertificates) > 64 {
			return ErrScopeUnavailable
		}
		certificates := C.CFArrayCreateMutable(0, 0, &C.kCFTypeArrayCallBacks)
		if certificates == 0 {
			return ErrScopeUnavailable
		}
		defer C.CFRelease(C.CFTypeRef(certificates))
		for _, certificate := range state.PeerCertificates {
			if certificate == nil || len(certificate.Raw) == 0 || len(certificate.Raw) > 1024*1024 {
				return ErrScopeUnavailable
			}
			ok := C.amneziaAppendCertificate(certificates, unsafe.Pointer(&certificate.Raw[0]), C.CFIndex(len(certificate.Raw)))
			runtime.KeepAlive(certificate)
			if ok == 0 {
				return ErrScopeUnavailable
			}
		}
		name := []byte(strings.TrimSuffix(selected.ServerName, ".") + "\x00")
		if len(state.OCSPResponse) > 1024*1024 || len(state.SignedCertificateTimestamps) > 256 {
			return ErrScopeUnavailable
		}
		var ocsp C.CFDataRef
		if len(state.OCSPResponse) != 0 {
			ocsp = C.CFDataCreate(0, (*C.UInt8)(unsafe.Pointer(&state.OCSPResponse[0])), C.CFIndex(len(state.OCSPResponse)))
			if ocsp == 0 {
				return ErrScopeUnavailable
			}
			defer C.CFRelease(C.CFTypeRef(ocsp))
		}
		var timestamps C.CFMutableArrayRef
		if len(state.SignedCertificateTimestamps) != 0 {
			timestamps = C.CFArrayCreateMutable(0, 0, &C.kCFTypeArrayCallBacks)
			if timestamps == 0 {
				return ErrScopeUnavailable
			}
			defer C.CFRelease(C.CFTypeRef(timestamps))
			for _, timestamp := range state.SignedCertificateTimestamps {
				if len(timestamp) == 0 || len(timestamp) > 65535 ||
					C.amneziaAppendData(timestamps, unsafe.Pointer(&timestamp[0]), C.CFIndex(len(timestamp))) == 0 {
					return ErrScopeUnavailable
				}
			}
		}
		accepted := C.amneziaVerifyCachedSSL(C.CFArrayRef(certificates), (*C.char)(unsafe.Pointer(&name[0])),
			ocsp, C.CFArrayRef(timestamps))
		runtime.KeepAlive(state)
		if accepted == 0 {
			return ErrScopeUnavailable
		}
		runtime.KeepAlive(name)
		if previous != nil {
			return previous(state)
		}
		return nil
	}
	return selected, nil
}

func darwinRootSnapshot() (*x509.CertPool, error) {
	certificates := C.amneziaLocalTrustCertificates()
	if certificates == 0 {
		return nil, ErrScopeUnavailable
	}
	defer C.CFRelease(C.CFTypeRef(certificates))
	count := C.CFArrayGetCount(certificates)
	if count < 1 || count > 16384 {
		return nil, ErrScopeUnavailable
	}
	roots := x509.NewCertPool() // SystemCertPool would re-enable the online verifier.
	for i := C.CFIndex(0); i < count; i++ {
		data := C.amneziaCertificateData(certificates, i)
		if data == 0 {
			return nil, ErrScopeUnavailable
		}
		size := C.CFDataGetLength(data)
		if size < 1 || size > 1024*1024 {
			C.CFRelease(C.CFTypeRef(data))
			return nil, ErrScopeUnavailable
		}
		der := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(size))
		C.CFRelease(C.CFTypeRef(data))
		certificate, err := x509.ParseCertificate(der)
		if err == nil {
			roots.AddCert(certificate)
		}
	}
	if len(roots.Subjects()) == 0 {
		return nil, ErrScopeUnavailable
	}
	return roots, nil
}

func darwinCertificateTrustAbsent(der []byte) (bool, error) {
	if len(der) == 0 || len(der) > 1024*1024 {
		return false, ErrScopeUnavailable
	}
	result := C.amneziaCertificateTrustAbsent(unsafe.Pointer(&der[0]), C.CFIndex(len(der)))
	runtime.KeepAlive(der)
	switch result {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, fmt.Errorf("%w: read local Darwin certificate trust settings (%d)", ErrScopeUnavailable, int(result))
	}
}
