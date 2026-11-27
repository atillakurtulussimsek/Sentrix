**Türkçe** · [English](../proxmox.md)

# Proxmox VE anlık görüntü entegrasyonu

Sentrix bir sanal makineyi ya da konteyneri yamalamadan hemen önce anlık görüntüsünü alabilir ve anlık görüntü
başarısız olursa o sunucu için işlemi iptal edebilir.

1. Proxmox'ta **bir API anahtarı oluşturun**: *Datacenter → Permissions → API Tokens → Add* (ör. kullanıcı
   `sentrix@pve`, anahtar kimliği `patch`). Anahtara (ya da ayrıcalık ayrımı kapalıysa kullanıcısına), Sentrix'in
   anlık görüntü alacağı sanal makineler/havuzlar üzerinde `VM.Snapshot` (ve `VM.Audit`) yetkisi içeren bir rol verin.
2. **Kancayı ekleyin** — *Ayarlar → Anlık görüntü kancaları*: API URL'si (`https://pve.example.com:8006`), anahtar
   kimliği (`sentrix@pve!patch`) ve sır. Kendinden imzalı sertifikalarda doğrulamayı kapatmak yerine sertifikanın
   SHA-256 parmak izini (*Node → System → Certificates*) yapıştırın. **Bağlantıyı test et** düğmesine tıklayın.
3. **Sunucuları eşleyin** — her sunucunun *Yamalar ve eylemler* sekmesinde: düğüm adı ve VM kimliği (QEMU için `105`,
   konteyner için `lxc/105`). Kanca üzerinde varsayılan bir düğüm ayarlanabilir.
4. **Kullanın** — bir yama planında ya da politikada (anlık görüntü kancası + "anlık görüntüsü başarısız olan sunucuyu
   iptal et").

Anlık görüntüler `sentrix-<plan>-<UTC timestamp>` (plan adı ve UTC zaman damgası) biçiminde adlandırılır ve plan
adıyla açıklanır. Sentrix anlık görüntüleri silmez — yamalanan sistemi doğruladıktan sonra onları kaldırın.

## Genel webhook kancası

Diğer anlık görüntü mekanizmaları (ZFS, LVM, bulut API'leri, yedekleme araçları) bir webhook ile tetiklenebilir:
Sentrix şu içeriği POST eder

```json
{"event": "pre_patch", "target": {"plan_id": "…", "plan_name": "…", "host_id": "…", "hostname": "web-1"}, "time": "…"}
```

ve bir sır ayarlanmışsa `X-Sentrix-Signature: sha256=<HMAC>` başlığını ekler. Anlık görüntü tamamlandığında 2xx
ile yanıt verin (isteğe bağlı olarak `{"snapshot": "name"}`); diğer her yanıt başarısız bir anlık görüntü sayılır.
