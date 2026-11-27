**Türkçe** · [English](../notifications.md)

# Alarmlar ve bildirimler

Bildirimler sunucunun varsayılan dilinde gönderilir: `language` /
`SENTRIX_LANGUAGE` (varsayılan `tr`; bkz. [yapılandırma](configuration.md#dil)).

## Kanallar (*Ayarlar → Bildirim kanalları*)

| Tür | Gerekenler | Notlar |
|---|---|---|
| Genel webhook | URL, isteğe bağlı HMAC sırrı | JSON gövdesi `{event, severity, title, body, host, host_id, alert_id, rule, value, url, time}`; başlık `X-Sentrix-Signature: sha256=<hex HMAC of the body>` (gövdenin onaltılık HMAC değeri) |
| Slack | gelen webhook URL'si | |
| Discord | kanal webhook URL'si | |
| Telegram | bot anahtarı (@BotFather'dan), sohbet kimliği | |
| ntfy | sunucu URL'si (varsayılan `https://ntfy.sh`), konu, isteğe bağlı erişim anahtarı | kritik için öncelik 5, uyarı için 4 |
| E-posta | SMTP sunucusu, port, STARTTLS/TLS, kullanıcı adı/parola, gönderen, alıcı | kimlik bilgileri asla TLS olmadan gönderilmez |

Bir kanala test mesajı göndermek için yanındaki **test** düğmesini kullanın. Anahtarlar, sırlar ve parolalar
depolanırken şifrelenir. Her gönderim denemesi gönderim günlüğünde listelenir.

## Kurallar (*Alarmlar*)

Varsayılan kurallar ilk başlangıçta oluşturulur: ajan çevrimdışı (5 dk), disk > %90 (5 dk), inode > %90, başarısız
systemd birimleri, izlenen servis çalışmıyor, 7 gündür bekleyen yeniden başlatma, yeni KEV zafiyeti, yeni kritik
zafiyet, yama planı sonucu.

- **threshold (eşik)** — metrik (`disk.used_pct`, `mem.used_pct`, `cpu.usage`, `load.1`, `net.rx_bps`, …), isteğe
  bağlı tam etiket kümesi (`mount=/`, `iface=eth0`), işleç ve değer.
- **state (durum)** — `agent_offline`, `failed_units`, `service_down` (sunucunun *izlenen servisler* listesindeki
  birimler), `reboot_pending`.
- **vulnerability (zafiyet)** — KEV listesinde olan ve/veya en az belirli bir önem derecesine sahip yeni bulgular.
- **patch (yama)** — plan tamamlandı ya da başarısız oldu.

Alarm yaşam döngüsü: alarmın *tetiklenmesi* (tek bildirim) için koşulun **for** süresi boyunca sürmesi gerekir.
Tetiklenmiş durumdayken bildirim ancak **bekleme süresi** (cooldown) dolduktan sonra yinelenir; koşul ortadan
kalktığında bir **çözüldü** mesajı gönderilir. Aynı alarm, son bildiriminin bekleme süresi içinde yeniden
tetiklenirse (dalgalanma), sessizce tetiklenir.

## Özet

"İlgilenilmesi gerekenler" özetini almak için bir cron zamanlaması (ör. `CRON_TZ=Europe/Istanbul 0 8 * * MON-FRI`)
ve kanallar ayarlayın: çevrimdışı sunucular, en yüksek riskler, bekleyen (güvenlik) güncellemeleri, bekleyen yeniden
başlatmalar.
