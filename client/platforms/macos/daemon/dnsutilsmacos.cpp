/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "dnsutilsmacos.h"
#include "macosdnsrecovery.h"

#include <systemconfiguration/scdynamicstore.h>
#include <systemconfiguration/scpreferences.h>

#include <QScopeGuard>

#include "leakdetector.h"
#include "logger.h"

namespace {
Logger logger("DnsUtilsMacos");
}

DnsUtilsMacos::DnsUtilsMacos(QObject* parent) : DnsUtils(parent) {
  MZ_COUNT_CTOR(DnsUtilsMacos);

  m_scStore = SCDynamicStoreCreate(kCFAllocatorSystemDefault,
                                   CFSTR("amneziavpn"), nullptr, nullptr);
  if (m_scStore == nullptr) {
    logger.error() << "Failed to create system configuration store ref";
  }

  logger.debug() << "DnsUtilsMacos created.";
}

DnsUtilsMacos::~DnsUtilsMacos() {
  MZ_COUNT_DTOR(DnsUtilsMacos);
  restoreResolversForCurrentOwner();
  logger.debug() << "DnsUtilsMacos destroyed.";
}

static QString cfParseString(CFTypeRef ref) {
  if (CFGetTypeID(ref) != CFStringGetTypeID()) {
    return QString();
  }

  CFStringRef stringref = (CFStringRef)ref;
  CFRange range;
  range.location = 0;
  range.length = CFStringGetLength(stringref);
  if (range.length <= 0) {
    return QString();
  }

  UniChar* buf = (UniChar*)malloc(range.length * sizeof(UniChar));
  if (!buf) {
    return QString();
  }
  auto guard = qScopeGuard([&] { free(buf); });

  CFStringGetCharacters(stringref, range, buf);
  return QString::fromUtf16(buf, range.length);
}

static QStringList cfParseStringList(CFTypeRef ref) {
  if (CFGetTypeID(ref) != CFArrayGetTypeID()) {
    return QStringList();
  }

  CFArrayRef array = (CFArrayRef)ref;
  QStringList result;
  for (CFIndex i = 0; i < CFArrayGetCount(array); i++) {
    CFTypeRef value = CFArrayGetValueAtIndex(array, i);
    result.append(cfParseString(value));
  }

  return result;
}

static void cfDictSetString(CFMutableDictionaryRef dict, CFStringRef name,
                            const QString& value) {
  if (value.isNull()) {
    return;
  }
  CFStringRef cfValue = CFStringCreateWithCString(
      kCFAllocatorSystemDefault, qUtf8Printable(value), kCFStringEncodingUTF8);
  CFDictionarySetValue(dict, name, cfValue);
  CFRelease(cfValue);
}

static void cfDictSetStringList(CFMutableDictionaryRef dict, CFStringRef name,
                                const QStringList& valueList) {
  if (valueList.isEmpty()) {
    return;
  }

  CFMutableArrayRef array;
  array = CFArrayCreateMutable(kCFAllocatorSystemDefault, 0,
                               &kCFTypeArrayCallBacks);
  if (array == nullptr) {
    return;
  }

  for (const QString& rstring : valueList) {
    CFStringRef cfAddr = CFStringCreateWithCString(kCFAllocatorSystemDefault,
                                                   qUtf8Printable(rstring),
                                                   kCFStringEncodingUTF8);
    CFArrayAppendValue(array, cfAddr);
    CFRelease(cfAddr);
  }
  CFDictionarySetValue(dict, name, array);
  CFRelease(array);
}

bool DnsUtilsMacos::updateResolversNative(const QString& ifname,
                                     const QList<QHostAddress>& resolvers, bool strict) {
  Q_UNUSED(ifname);
  if (strict) {
    return !m_dnsRecovery.isEmpty() && MacosDnsRecovery::apply(m_scStore, m_dnsRecovery, false);
  }

  // Get the list of current network services.
  CFArrayRef netServices = SCDynamicStoreCopyKeyList(
      m_scStore, CFSTR("Setup:/Network/Service/[0-9A-F-]+"));
  if (netServices == nullptr) {
    return false;
  }
  auto serviceGuard = qScopeGuard([&] { CFRelease(netServices); });

  // Prepare the DNS configuration.
  CFMutableDictionaryRef dnsConfig = CFDictionaryCreateMutable(
      kCFAllocatorSystemDefault, 0, &kCFCopyStringDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  if (!dnsConfig) return false;
  auto configGuard = qScopeGuard([&] { CFRelease(dnsConfig); });
  QStringList list;
  for (const QHostAddress& addr : resolvers) {
    list.append(addr.toString());
  }
  cfDictSetStringList(dnsConfig, kSCPropNetDNSServerAddresses, list);
  cfDictSetString(dnsConfig, kSCPropNetDNSDomainName, "lan");
  if (strict && !CFDictionaryContainsKey(dnsConfig, kSCPropNetDNSServerAddresses)) return false;

  // Backup each network service's DNS config, and replace it with ours.
  for (CFIndex i = 0; i < CFArrayGetCount(netServices); i++) {
    QString service = cfParseString(CFArrayGetValueAtIndex(netServices, i));
    QString uuid = service.section('/', 3, 3);
    if (uuid.isEmpty()) {
      continue;
    }
    backupService(uuid);

    logger.debug() << "Setting DNS config for" << uuid;
    CFStringRef dnsPath = CFStringCreateWithFormat(
        kCFAllocatorSystemDefault, nullptr,
        CFSTR("Setup:/Network/Service/%s/DNS"), qPrintable(uuid));
    if (!dnsPath) {
      if (strict) return false;
      continue;
    }
    const bool success = SCDynamicStoreSetValue(m_scStore, dnsPath, dnsConfig);
    CFRelease(dnsPath);
    if (strict && !success) return false;
  }
  return true;
}

bool DnsUtilsMacos::restoreResolversNative(bool strict) {
  if (strict && !m_dnsRecovery.isEmpty()) {
    if (!MacosDnsRecovery::apply(m_scStore, m_dnsRecovery, true)) return false;
    m_dnsRecovery = {};
    return true;
  }
  for (const QString& uuid : m_prevServices.keys()) {
    CFStringRef path = CFStringCreateWithFormat(
        kCFAllocatorSystemDefault, nullptr,
        CFSTR("Setup:/Network/Service/%s/DNS"), qPrintable(uuid));
    if (!path) { if (strict) return false; continue; }

    logger.debug() << "Restoring DNS config for" << uuid;
    const DnsBackup& backup = m_prevServices[uuid];
    bool success = false;
    if (backup.isValid()) {
      CFMutableDictionaryRef config;
      config = CFDictionaryCreateMutable(kCFAllocatorSystemDefault, 0,
                                         &kCFCopyStringDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);
      if (!config) { CFRelease(path); return false; }

      cfDictSetString(config, kSCPropNetDNSDomainName, backup.m_domain);
      cfDictSetStringList(config, kSCPropNetDNSSearchDomains, backup.m_search);
      cfDictSetStringList(config, kSCPropNetDNSServerAddresses,
                          backup.m_servers);
      cfDictSetStringList(config, kSCPropNetDNSSortList, backup.m_sortlist);
      success = SCDynamicStoreSetValue(m_scStore, path, config);
      CFRelease(config);
    } else {
      success = SCDynamicStoreRemoveValue(m_scStore, path);
      if (!success && SCError() == kSCStatusNoKey) success = true;
    }
    CFRelease(path);
    if (strict && !success) return false;
  }

  m_prevServices.clear();
  return true;
}

bool DnsUtilsMacos::prepareDnsRecovery(NativeDnsGuard &guard, const QString &ifname,
                                     const QList<QHostAddress> &endpoints) {
  Q_UNUSED(ifname);
  const auto snapshot = MacosDnsRecovery::capture(m_scStore, endpoints, m_dnsRecovery);
  if (snapshot.isEmpty() || !guard.storeDnsRecovery(snapshot)) return false;
  m_dnsRecovery = snapshot;
  return true;
}

void DnsUtilsMacos::backupService(const QString& uuid) {
  if (m_prevServices.contains(uuid)) return; // Retain the pre-VPN snapshot across updates.
  DnsBackup backup;
  CFStringRef path = CFStringCreateWithFormat(
      kCFAllocatorSystemDefault, nullptr,
      CFSTR("Setup:/Network/Service/%s/DNS"), qPrintable(uuid));
  CFDictionaryRef config =
      (CFDictionaryRef)SCDynamicStoreCopyValue(m_scStore, path);
  auto serviceGuard = qScopeGuard([&] {
    if (config) {
      CFRelease(config);
    }
    CFRelease(path);
  });

  // Parse the DNS protocol entry and save it for later.
  if (config) {
    CFTypeRef value;
    value = CFDictionaryGetValue(config, kSCPropNetDNSDomainName);
    if (value) {
      backup.m_domain = cfParseString(value);
    }
    value = CFDictionaryGetValue(config, kSCPropNetDNSServerAddresses);
    if (value) {
      backup.m_servers = cfParseStringList(value);
    }
    value = CFDictionaryGetValue(config, kSCPropNetDNSSearchDomains);
    if (value) {
      backup.m_search = cfParseStringList(value);
    }
    value = CFDictionaryGetValue(config, kSCPropNetDNSSortList);
    if (value) {
      backup.m_sortlist = cfParseStringList(value);
    }
  }

  m_prevServices[uuid] = backup;
}
