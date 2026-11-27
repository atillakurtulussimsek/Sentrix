**Türkçe** · [English](../install.md)

# Kurulum

## Sunucu

### Docker / Docker Compose (önerilen)

```bash
curl -fsSLO https://raw.githubusercontent.com/atillakurtulussimsek/Sentrix/main/docker-compose.yml
SENTRIX_HOST=sentrix.example.com docker compose up -d
```

- Varsayılan dil Türkçedir. İngilizce için `docker-compose.yml` dosyasında `environment:` altına
  `SENTRIX_LANGUAGE: en` ekleyin (desteklenenler: `tr`, `en`). Her kullanıcı yine de kendi arayüz dilini seçebilir.
- Veriler (SQLite veritabanı, dahili CA, gizli anahtar, veri kaynağı önbelleği) `sentrix-data` biriminde (`/data`)
  tutulur. **Yedekleyin**, ancak `secret.key` ve `pki/ca.key` dosyalarını güvenilmeyen depolama alanlarından uzak tutun.
- İmaj, distroless bir taban üzerinde ayrıcalıksız bir kullanıcıyla çalışır ve yerleşik bir sağlık denetimine sahiptir.
- İmaj ayrıca `linux/amd64` ve `linux/arm64` için ajan ikili dosyalarını içerir; bunlar `install.sh` tek satırlık
  komutu için `/download/` altında sunulur, böylece sunucuların GitHub'a erişmesi hiç gerekmez.

### Dokploy / Traefik / diğer ters vekiller (reverse proxy)

- HTTPS alan adınızı (ör. `sentrix.example.com`) konteynerin **8080** portuna (web arayüzü/API) yönlendirin ve
  `SENTRIX_BASE_URL=https://sentrix.example.com` değerini ayarlayın. Çerezler otomatik olarak `Secure` olur.
- **8443** portunu doğrudan (ya da bir TCP rotası / TLS passthrough olarak) yayımlayın. Bu port ters vekil tarafından
  **sonlandırılmamalıdır**: ajanlar istemci sertifikalarıyla kimlik doğrular.
  `SENTRIX_GATEWAY_URL=https://sentrix.example.com:8443` değerini ayarlayın.
- Sunucudaki 8080 ya da 8443 portu doluysa ("port is already allocated"), servis ortamına `SENTRIX_UI_PORT` /
  `SENTRIX_GATEWAY_PORT` ekleyin (ör. `SENTRIX_UI_PORT=8090`); varsayılan adresler bu portlara göre oluşur.

### Paketler (.deb / .rpm) ve ikili dosyalar

Sürüm dosyaları `sentrix-server` ve `sentrix-agent` paketlerini ve düz ikili dosyaları içerir.

```bash
sudo apt install ./sentrix-server_0.1.0_linux_amd64.deb
sudoedit /etc/sentrix/server.yaml      # base_url, gateway_url, gateway_hosts
sudo systemctl enable --now sentrix-server
```

Sunucu birimi, systemd korumalı alanıyla (sandboxing) `sentrix` kullanıcısı olarak çalışır
(`deploy/systemd/sentrix-server.service`).

### Ters vekil olmadan arayüz için TLS

`server.yaml` içinde `tls_cert` ve `tls_key` değerlerini (PEM dosyaları) ayarlayın. Ajan geçidi her zaman
Sentrix'in dahili CA'sını kullanır.

### İlk çalıştırma

Arayüzü açın: sihirbaz ilk yöneticiyi oluşturur ve sorumluluk reddini kabul etmenizi ister. Arayüzsüz alternatif:
`sentrix-server user create --username admin --role admin` (parola `SENTRIX_PASSWORD` değişkeninden ya da
standart girdiden okunur).

## Ajan

### Tek satırlık komut (önerilen)

*Ayarlar → Kayıt → Anahtar oluştur* şuna benzer bir komut gösterir:

```bash
curl -fsSL https://sentrix.example.com/install.sh | sudo sh -s -- --token sxe_… --ca-fingerprint …
```

Komut, ajanı sunucunuzdan indirir, `/etc/sentrix/agent.yaml` dosyasını yazar, kaydı yapar (tek kullanımlık anahtar +
CA parmak izi sabitleme) ve bir systemd birimi kurar. Seçenekler: `--hostname`, `--no-patching` (salt okunur ajan),
`--server`, `--download-url`, `--lang tr|en` (kurulum betiğinin dili, varsayılan `tr`).

### Paket

```bash
sudo apt install ./sentrix-agent_0.1.0_linux_amd64.deb      # or dnf install ./…rpm
sudo sentrix-agent --config /etc/sentrix/agent.yaml enroll --server https://sentrix.example.com:8443 --token sxe_… --ca-fingerprint …
sudo systemctl enable --now sentrix-agent
```

RPM tabanlı dağıtımlarda `apt install` yerine `dnf install ./…rpm` kullanın.

### Bir sunucuyu kaldırma

*Sunucu → Yamalar ve eylemler → Tehlikeli bölge*: **İptal et**, ajanın erişimini hemen keser (sertifika seri
numarası reddedilir); **Sil**, sunucuyu ve verilerini kaldırır. Sunucunun kendisinde: `systemctl disable --now
sentrix-agent && rm -rf /var/lib/sentrix-agent /etc/sentrix /usr/local/bin/sentrix-agent`.

## Yükseltme

Yeni imajı çekin (`docker compose pull && docker compose up -d`) ya da yeni paketleri kurun. Veritabanı geçişleri
başlangıçta otomatik olarak çalışır. Ajanlar 0.x küçük sürümleri içinde geriye dönük uyumludur.
