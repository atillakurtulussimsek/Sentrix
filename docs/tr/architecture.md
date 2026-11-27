**Türkçe** · [English](../architecture.md)

# Mimari

```
┌──────────────────── Sentrix server (one binary / container) ────────────────────┐
│ Web UI (HTMX, Tailwind, uPlot) · REST API · Agent gateway (mTLS, :8443)           │
│ Vuln engine (feed sync + local matcher) · Patch orchestrator · Policy scheduler   │
│ Alert engine + notifier · Audit log · SQLite (WAL)                                │
└────────────────────────────────▲────────────────────────────────────────────────┘
                                 │ outbound HTTPS + client certificate from every host
            ┌────────────────────┴────────────┐
            │ sentrix-agent (static binary)   │  collectors (/proc, statfs, systemd, Docker API)
            │ inventory (dpkg/rpm/apk, ports) │  on-disk buffer · long-poll commands
            │ typed action executor           │  (apt-get / dnf / apk / systemctl, argv only)
            └─────────────────────────────────┘
```

Şemanın özeti: Sentrix sunucusu (tek ikili dosya / konteyner) web arayüzünü (HTMX, Tailwind, uPlot), REST API'yi,
ajan geçidini (mTLS, :8443), zafiyet motorunu (veri kaynağı eşitleme + yerel eşleştirici), yama düzenleyicisini,
politika zamanlayıcısını, alarm motorunu ve bildiriciyi, denetim kaydını ve SQLite (WAL) veritabanını içerir.
Her sunucudaki `sentrix-agent` (statik ikili dosya) sunucuya dışa doğru HTTPS ve istemci sertifikasıyla bağlanır;
toplayıcıları (/proc, statfs, systemd, Docker API), envanteri (dpkg/rpm/apk, portlar), disk arabelleği,
uzun yoklamayla (long-poll) komut alımı ve tipli eylem yürütücüsü (apt-get / dnf / apk / systemctl, yalnızca argv)
vardır.

## Paketler

| Paket | Sorumluluk |
|---|---|
| `internal/protocol` | iletişim tipleri; kapalı `Action` kümesi ve katı doğrulaması |
| `internal/pki` | dahili CA, CSR imzalama, sunucu zinciri doğrulaması |
| `internal/agent` (+ `collect`, `inventory`, `executor`) | ajan çalışma zamanı, toplayıcılar, envanter ayrıştırıcıları, yürütücü |
| `internal/store` | SQLite kalıcılığı, gömülü geçişler, metrik katmanları (`MetricStore` arayüzü) |
| `internal/vuln` (+ `version`) | veri kaynağı ayrıştırıcıları, dağıtım sürüm karşılaştırıcıları, eşleştirici, risk puanı |
| `internal/patch` | bakım pencereleri, kanarya zamanlaması, politika kararları, anlık görüntü kancaları |
| `internal/notify` | kanal göndericileri, kural yapılandırması, alarm durum geçişleri |
| `internal/auth` | argon2id, TOTP, AES-GCM sır kutusu, hız sınırlayıcı |
| `internal/server` | HTTP işleyicileri, düzenleme döngüleri, işler |
| `web` | şablonlar, statik dosyalar, i18n katalogları (gömülü; Türkçe ve İngilizce) |

## Veri akışı

1. **Kayıt** — ajan CA'yı indirir, SHA-256 değerini anahtarla birlikte verilen parmak iziyle karşılaştırır, bir CSR +
   tek kullanımlık kayıt anahtarı gönderir ve bir istemci sertifikası alır (CN = sunucu kimliği). Anahtar atomik
   olarak tüketilir.
2. **Telemetri** — ajan her 10 sn'de bir metrikleri belleğe örnekler; her 30 sn'de bir gzip ile sıkıştırılmış bir
   paketi disk arabelleğine yazar ve arabelleği sunucuya boşaltır (en eskiden başlayarak; yalnızca başarı durumunda
   silinir). Durum (süreçler, birimler, konteynerler, yeniden başlatma) her 30 sn'de; envanter başlangıçta, her 6 saatte
   ve yamalardan sonra gönderilir.
3. **Depolama** — ham örnekler (24 sa), gecikmeli (arabelleğe alınmış) verilerin de dahil edilmesi için küçük bir
   örtüşmeyi yeniden toplayan bir eşik işaretli iş tarafından her dakika 1 dakikalık (7 gün) ve 1 saatlik (90 gün)
   katmanlara özetlenir.
4. **Zafiyetler** — filoda bulunan dağıtımların veri kaynakları indirilir (ETag'e duyarlı) ve
   `vuln_affected(ecosystem, package, vuln, fixed)` biçimine normalleştirilir. Her envanter ve veri kaynağı
   eşitlemesinden sonra her sunucunun paketleri dağıtımın karşılaştırıcısıyla eşleştirilir; bulgular açıklamalı bir
   risk puanıyla saklanır.
5. **Yamalama** — bir plan, tek bir düzenleyici döngüsünün ilerlettiği bir durum makinesinde sunucu başına bir satırdır
   (`pending → dry_run → dry_ok → snapshot → patching → rebooting → verifying → done/failed`). Komutlar
   veritabanında kuyruğa alınır ve ajanın uzun yoklaması üzerinden iletilir; sonuçlar idempotenttir (komut kimlikleri).
6. **Alarmlar** — kurallar her 15 sn'de bir (eşikler, durum) ya da olaylar üzerine (yeni bulgular, plan sonuçları)
   değerlendirilir; alarm örnekleri `for`, bekleme süresi ve dalgalanma bastırma ile `pending → firing → resolved`
   yolunu izler. Bildirimler sunucunun varsayılan dilinde gönderilir.

## Tasarım kararları

ADR kaydı (iletim, depolama, veri kaynakları, eşleştirme anlambilimi, arayüz derlemesi) için bkz.
[DECISIONS.md](../DECISIONS.md) (İngilizce).
