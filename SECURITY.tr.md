**Türkçe** · [English](SECURITY.md)

# Güvenlik politikası

## Bir zafiyeti bildirme

Güvenlik sorunları için lütfen **herkese açık bir issue açmayın**. Bunları GitHub Security Advisories üzerinden
(deponun Security sekmesindeki "Report a vulnerability") gizli olarak bildirin. Etkilenen sürümü, bir açıklamayı ve
yeniden üretme adımlarını ekleyin. Bildirimleri 3 iş günü içinde yanıtlamayı ve yüksek önem dereceli sorunlar için
30 gün içinde bir düzeltme ya da hafifletme yayımlamayı hedefliyoruz. Aksini istemediğiniz sürece adınız anılır.

Desteklenen sürümler: güvenlik düzeltmelerini en son küçük sürüm alır.

## Tehdit modeli (özet)

Sentrix birçok sunucudaki yazılımı değiştirebildiği için tasarım; ağın, tek tek ajanların ve tek tek kullanıcı
hesaplarının ele geçirilebileceğini varsayar ve her birinin etki alanını sınırlar.

| Varlık / sınır | Tehdit | Önlem |
|---|---|---|
| Ajan ↔ sunucu kanalı | dinleme, kimliğe bürünme | TLS 1.2+, dahili bir CA'dan ajan başına sertifikalarla karşılıklı TLS; ajanlar kayıt sırasında CA'yı SHA-256 parmak iziyle sabitler; ajanlar geçidi zincir + `ServerAuth` EKU ile doğrular (ajan sertifikaları yalnızca `ClientAuth` içerir ve asla sunucunun kimliğine bürünemez) |
| Kayıt | yetkisiz bir sunucu filoya katılır | tek kullanımlık, süresi dolan kayıt anahtarları (yalnızca SHA-256 özeti saklanır); başarısız denemeler IP başına hız sınırlamasına tabidir |
| Ele geçirilmiş sunucu ya da arayüz hesabı | her sunucuda rastgele kod çalıştırma | **uzak kabuk yok**: ajanlar yalnızca kapalı bir tipli eylem kümesini (`refresh_inventory`, `scan`, `patch_packages`, `patch_security_only`, `patch_all`, `reboot`, `restart_service`) katı biçimde doğrulanan parametrelerle kabul eder (bilinmeyen JSON alanları reddedilir; paket ve birim adları temkinli kalıplarla eşleştirilir); yürütücü yalnızca izin listesindeki programları argv ile çalıştırır (asla bir kabukla değil). Ajanlar `allow_patching: false` ile salt okunur yapılabilir. |
| Ele geçirilmiş ajan | sunucuya ya da diğer sunuculara saldırı | ajanlar yalnızca `/agent/v1/*` adreslerine erişir; her istek ajanın sertifikasına ve güncel seri numarasına bağlıdır (iptal); yük boyutları sınırlıdır; ajanlar diğer sunucular hakkında asla veri almaz |
| Kesintiye yol açan yama | bozulan üretim sistemleri | otomatik yamalama **varsayılan olarak kapalıdır**; her plan önce deneme çalıştırması yapar ve açık onay gerektirir; kanarya dağıtımı ilk hatada durur; isteğe bağlı yama öncesi anlık görüntüler (Proxmox/webhook) başarısız olursa o sunucu iptal edilir; politikalar için bakım pencereleri; eksiksiz denetim kaydı |
| Web arayüzü | oturum çalma, CSRF, XSS, clickjacking | argon2id parolalar, isteğe bağlı TOTP 2FA, sunucu tarafı oturumlar (yalnızca özetler saklanır), `HttpOnly`+`SameSite=Lax`(+HTTPS'te `Secure`) çerezler, oturum başına CSRF anahtarları + Origin denetimi, katı CSP (`script-src 'self'`, satır içi betik yok), `X-Frame-Options: DENY`, giriş hız sınırlaması, sunucu tarafında uygulanan roller (admin/operator/viewer) |
| API anahtarları | sızdırılmış otomasyon kimlik bilgileri | kapsamlı anahtarlar (read/operate/admin, asla sahibinin rolünün üzerinde değil), isteğe bağlı bitiş tarihi, yalnızca SHA-256 özeti saklanır, iptal edilebilir, başarısız bearer denemeleri hız sınırlamasına tabidir |
| Depolanan sırlar | veritabanı hırsızlığı kanal anahtarlarını / Proxmox kimlik bilgilerini / TOTP tohumlarını açığa çıkarır | sunucu anahtarıyla AES-256-GCM (`data_dir/secret.key` ya da `SENTRIX_SECRET_KEY`) — anahtarı veritabanı yedeklerinin dışında tutun |
| Zafiyet verileri | zehirlenmiş veri kaynağı / gizlilik | veri kaynakları projelerin resmi konumlarından HTTPS üzerinden alınır; eşleştirme yerel olarak yapılır, **hiçbir sunucu verisi üçüncü taraflara gönderilmez** |
| Tedarik zinciri | kötü amaçlı bağımlılık | küçük bağımlılık kümesi (bkz. `docs/DECISIONS.md`), statik ikili dosyalar, GoReleaser ile yeniden üretilebilir derlemeler, yarış dedektörü ve linter'lar içeren CI |

### Kapsam dışı / bilinen sınırlamalar
- Ajan root olarak çalışır (paket kurması gerekir). `/var/lib/sentrix-agent` dizinini (anahtar materyali, mod 0600)
  koruyun.
- Dahili CA anahtarı `data_dir/pki/ca.key` içinde bulunur; ona sahip olan herkes ajan sertifikası üretebilir.
- Sentrix dağıtımların güvenlik bildirimi verilerine güvenir; eksik bir bildirim, eksik bir bulgu demektir.
- Veri kaynağı indirmeleri standart proxy ortam değişkenlerine uyar; TLS dışında veri kaynağı imza doğrulaması
  yoktur.

OWASP ASVS Seviye 1 öz değerlendirmesi için bkz. `docs/security-review.md` (İngilizce).
