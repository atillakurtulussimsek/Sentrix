**Türkçe** · [English](../patch-policies.md)

# Yama planları ve politikalar

## Elle oluşturulan planlar (varsayılan)

1. *Yama planları → Yeni* (ya da bir sunucuda *Güvenlik yaması planla…*, veya `sentrix patch plan …`).
2. Sunucuları (ya da bir grubu), bir kapsamı — **yalnızca güvenlik**, **belirli paketler** ya da **tümü** —,
   yeniden başlatma davranışını (`never`, `if_required`, `always`), kanarya sayısını, paralelliği ve isteğe bağlı bir
   anlık görüntü kancasını seçin.
3. Sentrix her sunucuda bir **deneme çalıştırması** yapar ve tam paket geçişlerini (`from → to`) gösterir.
4. Bir operatör inceler ve **onaylar** (açık onay). Bundan önce hiçbir şey değişmez.
5. Dağıtım: önce ilk *kanarya* sunucular yamalanır (yapılandırılmışsa önce anlık görüntü alınır); geri kalanlar ancak
   tüm kanarya sunucular başarıyla tamamlandıktan sonra, aynı anda en fazla *azami paralellik* kadar başlatılır.
   **Herhangi bir hata dağıtımı durdurur.**
6. Her sunucu için: yama → (plan izin veriyorsa ve sunucu gerektiriyorsa yeniden başlatma; sunucu yeni bir açılış
   zamanıyla geri gelene kadar beklenir) → doğrulama (ajan çevrimiçi, güncel envanter, izlenen servisler etkin) →
   tamamlandı. Önceki/sonraki CVE sayıları kaydedilir; her şey denetim kaydında yer alır.

## Politikalar (otomatik yamalama)

Bir politika olmadan hiçbir şey asla otomatik olarak yamalanmaz (`notify_only`). Bir politika tek bir sunucu grubuna
uygulanır:

| Alan | Anlamı |
|---|---|
| mod | `notify_only`, `auto_security` (bekleyen güvenlik güncellemesi olan sunucular), `auto_all` |
| pencere | isteğe bağlı saat dilimli cron ifadesi, ör. `CRON_TZ=Europe/Istanbul 0 3 * * SUN`, artı dakika cinsinden bir süre |
| kanarya / azami paralellik | elle oluşturulan planlardaki gibi |
| yeniden başlatma | `never`, `if_required`, `always` |
| anlık görüntü kancası | isteğe bağlı; "zorunlu" ise anlık görüntüsü başarısız olan sunucu iptal edilir |

Kurallar: bir politika bir planı yalnızca bakım penceresinin **içinde**, **her pencere oluşumunda bir kez** başlatır;
önceki planı hâlâ etkinken asla başlatmaz ve yalnızca uygulanabilir güncellemesi olan çevrimiçi sunucular için
başlatır. Plan yine bir deneme çalıştırması yapar ve ancak deneme çalıştırması tamamlandıktan sonra otomatik olarak
onaylanır (`policy:<name>`). Pencere kapanırsa yeni sunucular başlatılmaz. Otomatik bir modu etkinleştirmek,
sorumluluk reddinin yeniden kabul edilmesini gerektirir.

## Yeniden başlatmalar

`reboot required` durumu `/var/run/reboot-required`, `needs-restarting -r` ve kurulu en yeni çekirdekten daha eski
olan çalışan bir çekirdek üzerinden algılanır. *7 gündür bekleyen yeniden başlatma* alarm kuralı, unutulan yeniden
başlatmaları size hatırlatır.
