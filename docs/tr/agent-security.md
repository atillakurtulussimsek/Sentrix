**Türkçe** · [English](../agent-security.md)

# Ajan eylemleri ve güvenlik modeli

## Temel özellik: uzak kabuk yok

Sunucu bir ajandan yalnızca şu eylemlerden birini yapmasını isteyebilir:

| Eylem | Parametreler | Sunucuda ne çalışır |
|---|---|---|
| `refresh_inventory`, `scan` | yok | envanter toplama (+ meta veri yenileme), gönderim |
| `patch_security_only` | yok | apt: `apt-get install --only-upgrade <security packages>`; dnf: `dnf -y upgrade --security`; (apk: sunucu tarafında çözümlenir) |
| `patch_packages` | `{"packages": [...]}` (1–500 ad) | `apt-get install --only-upgrade …` / `dnf -y upgrade -- …` / `apk upgrade …` |
| `patch_all` | yok | `apt-get upgrade --with-new-pkgs` / `dnf -y upgrade` / `apk upgrade` |
| `reboot` | `{"delay_seconds": 0..3600}` | `systemctl reboot` / `shutdown -r +N` |
| `restart_service` | `{"name": "unit"}` | `systemctl restart -- <unit>` |

Güvenceler (`internal/protocol/actions.go` ve `internal/agent/executor` içinde uygulanır;
`TestValidateRejectsUnknownAndRaw`, `TestNoArbitraryExecution`, `TestOnlyAllowedProgramsAndArgvSeparation`
testleriyle doğrulanır):

- Bilinmeyen eylemler, hiçbir şey çalışmadan reddedilir. Komut dizesi alan bir eylem yoktur.
- Parametreler katı biçimde çözümlenir (bilinmeyen JSON alanları → reddedilir).
- Paket adları `^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`, birim adları `^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,127}$` ile
  eşleşmelidir — hiçbir zaman `-` ile başlayamazlar (seçenek enjeksiyonu yok) ve kabuk meta karakteri içermezler.
- Yürütücü yalnızca `apt-get`, `dnf`, `yum`, `apk`, `systemctl`, `shutdown` programlarını başlatır; her zaman bir
  argv dizisiyle (asla bir kabuk üzerinden değil), sabit bir `PATH` ve `LC_ALL=C` ile.
- Envanter dışındaki her eylem **deneme çalıştırmasını** destekler; `allow_patching: false`, ajanın değişiklik yapan
  tüm eylemleri reddetmesini sağlar ancak deneme çalıştırmalarına yanıt vermeyi sürdürür.
- Komut kimlikleri iletimi idempotent kılar: bir ajan aynı komutu asla iki kez çalıştırmaz (son 200 komutun
  sonuçları `state_dir/commands.json` içinde tutulur).

## Kimlik ve iletim

- Tek kullanımlık kayıt anahtarları; sunucu yalnızca SHA-256 özetlerini saklar ve onları bir işlem (transaction)
  içinde tüketir.
- Ajan sunucu CA'sını parmak iziyle sabitler, ardından bir istemci sertifikası taşır (ECDSA P-256, 1 yıl,
  otomatik yenilenir).
- Sunucu, seri numarası sunucu kaydıyla artık eşleşmeyen sertifikaları reddeder (iptal anında etkili olur).
- Ajanlar yalnızca dışa doğru bağlanır; izlenen sunucularda hiçbir port açılmaz.

## Ajan ne gönderir

Metrikler, süreç adları ve kullanıcıları, systemd birim durumları, konteyner adları/imajları, kurulu paketler ve
sürümleri, bekleyen güncellemeler, süreç adlarıyla birlikte dinlenen portlar, işletim sistemi/çekirdek bilgileri.
Dosya içerikleri, komut satırları, ortam değişkenleri ve kimlik bilgileri gönderilmez.

## Neden root?

Tüm paket veritabanlarını ve `/proc/*/fd` dizinini (port sahipleri için) okumak ve güncellemeleri uygulamak root
yetkisi gerektirir. Yalnızca izleme ve zafiyet verisi istiyorsanız ajanı `allow_patching: false` ile çalıştırın.

## Kendi kendini güncelleme

Sunucu daha yeni bir ajan önerebilir (`update_agent`: sürüm, mimari ve SHA-256 değeri sabitlenmiş türlü bir
işlem). Ajan bildirimi ve ikili dosyayı mTLS bağlantısı üzerinden indirir ve yalnızca şu koşullarda kurar:

- bildirim **Varkhe Digital sürüm anahtarıyla** imzalanmışsa (Ed25519; açık anahtar ajanın içine derlenir, gizli
  anahtar yalnızca sürüm etiketi derlenirken kullanılan bir CI sırrı olarak bulunur),
- sürüm, mimari ve özet hem komutla hem imzalı bildirimle eşleşiyor ve dosya özetle uyuşuyorsa,
- sürüm çalışan ajandan yeniyse (eski sürüme dönüş yok).

Dosya atomik olarak değiştirilir ve ajan kendini yeniden çalıştırır (aynı PID; sunucu yeniden başlatılmaz).
Böylece ele geçirilmiş bir Sentrix sunucusu güncelleme *önerebilir*, ama yayımlanmamış ve imzalanmamış kodu
ajanlara çalıştıramaz. Bir sunucuyu dışarıda tutmak için `allow_self_update: false` ayarlayın; paketler
(.deb/.rpm) bu ayar kapalı gelir, çünkü dosyayı apt/dnf yönetir.
