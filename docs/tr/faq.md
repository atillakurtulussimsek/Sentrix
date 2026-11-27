**Türkçe** · [English](../faq.md)

# Sıkça sorulan sorular

**Sentrix paket listelerimi bir yere gönderiyor mu?**
Hayır. Zafiyet veri kaynakları sunucunuza indirilir ve eşleştirme yerel olarak yapılır. Dışa giden istekler veri
kaynaklarına (Debian, OSV/Google Cloud Storage, CISA, FIRST, NVD) ve kurduğunuz bildirim kanallarına gider.

**Bir CVE neden "henüz düzeltme yok" olarak görünüyor?**
Dağıtım sorunu kabul etmiş ancak düzeltilmiş bir paket yayımlamamıştır. Sentrix sizi etkilediği için onu yine de
listeler (daha düşük risk puanıyla); uygunsa bir bitiş tarihiyle kabul edin ya da yok sayın.

**CVE listesi X tarayıcısından farklı.**
Sentrix dağıtımın kendi güvenlik bildirimlerini ve sürüm kurallarını kullanır, bu yüzden backport edilmiş
düzeltmeler dikkate alınır (ör. upstream düzeltmeyi 3.0.14 olarak adlandırsa da `openssl 3.0.15-1~deb12u1`
düzeltilmiştir). Upstream sürümlerini karşılaştıran genel tarayıcılar çok sayıda yanlış pozitif bildirir.

**Rocky Linux?**
Rocky'nin kendi OSV dışa aktarımı eksik olduğundan, Rocky sunucuları ayrıca AlmaLinux bildirimleriyle de eşleştirilir
(aynı RHEL kaynakları ve paket sürümleri). Fedora ve RHEL'in kendisi izlenir ve envantere alınır, ancak v0.1'de
bunlar için bir zafiyet veri kaynağı yoktur.

**Sunucu, sunucularımda komut çalıştırabilir mi?**
Yalnızca [agent-security.md](agent-security.md) içinde listelenen tipli eylemleri. Uzak kabuk yoktur. Yalnızca
izleme yapılacak sunucular için `allow_patching: false` ayarlayın.

**Veritabanı ne kadar büyür?**
Metrikler: sunucu başına kabaca 150 seri; varsayılan saklama süreleriyle sunucu-yılı başına ~30–60 MB. Zafiyet
verileri: en büyük veri kaynağı Ubuntu'nunkidir (24.04 için ~750 bin satır, diskte birkaç yüz MB); diğerleri küçüktür.

**PostgreSQL kullanabilir miyim?**
Henüz değil — SQLite (WAL) yüzlerce sunucuyu rahatlıkla kaldırır. Depolama katmanı taşınabilir SQL kullandığından
PostgreSQL arka ucu yol haritasında yer alıyor.

**Yönetici parolasını / 2FA cihazını kaybettim.**
`sentrix-server user reset-password --username admin` (Docker'da: `docker compose exec sentrix …`). Bu komut 2FA'yı
temizler ve kullanıcının tüm oturumlarını kapatır; işlem denetim kaydına yazılır.

**NAT / güvenlik duvarı arkasındaki ajanlar?**
Ajanlar yalnızca sunucunun 8443 numaralı portuna dışa doğru HTTPS bağlantıları kurar. Sunucuya dışarıdan hiçbir
şeyin ulaşması gerekmez.

**İnternetten yalıtılmış (air-gapped) ortam?**
Veri kaynağı dosyalarını yansılayın ve `feeds.*_url` ayarlarını yansınıza yönlendirin; ajanlar sunucunun kendisinden
indirilir.

**Arayüzü İngilizce kullanabilir miyim?**
Evet. Her kullanıcı dilini kenar çubuğundaki, giriş sayfasındaki ya da *Hesap* ayarlarındaki seçiciden seçebilir.
Sunucunun varsayılan dilini (bildirimlerde de kullanılır) `SENTRIX_LANGUAGE=en` ile değiştirebilirsiniz; bkz.
[yapılandırma](configuration.md#dil).

### Yama uyguladım, çekirdek CVE'si neden hâlâ açık?

Yalnızca çalışan çekirdek dikkate alınır. Düzeltilmiş çekirdek kurulu ama sunucu yeniden başlatılmamışsa bulgu açık
kalır ve **yeniden başlatma gerekli** olarak işaretlenir. Yeniden başlatmadan (ve sonraki envanterden) sonra kapanır;
yedek olarak kurulu kalan eski çekirdekler yok sayılır.
