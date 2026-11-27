**Türkçe** · [English](../configuration.md)

# Yapılandırma başvurusu

Her iki ikili dosya da isteğe bağlı bir YAML dosyası okur (`--config FILE` ya da `SENTRIX_CONFIG` /
`SENTRIX_AGENT_CONFIG`) ve ardından öncelikli olan `SENTRIX_*` ortam değişkenlerini uygular. Süreler Go sözdizimini
kullanır (`30s`, `5m`, `72h`). Ortam değişkenlerindeki listeler virgülle ayrılır.

## Sunucu (`sentrix-server`)

| YAML anahtarı | Ortam değişkeni | Varsayılan | Anlamı |
|---|---|---|---|
| `data_dir` | `SENTRIX_DATA_DIR` | `./data` | veritabanı, `pki/` (dahili CA), `secret.key`, `feeds/` önbelleği |
| `listen` | `SENTRIX_LISTEN` | `:8080` | web arayüzü ve REST API |
| `tls_cert`, `tls_key` | `SENTRIX_TLS_CERT`, `SENTRIX_TLS_KEY` | – | arayüzü doğrudan HTTPS üzerinden sunar |
| `base_url` | `SENTRIX_BASE_URL` | `http://localhost:8080` | herkese açık arayüz URL'si (bildirimlerdeki bağlantılar, kurulum betiği, çerezin `Secure` bayrağı) |
| `gateway_listen` | `SENTRIX_GATEWAY_LISTEN` | `:8443` | ajan geçidi (karşılıklı TLS) |
| `gateway_url` | `SENTRIX_GATEWAY_URL` | `https://localhost:8443` | ajanların kullandığı URL (kurulum komutlarında gösterilir) |
| `gateway_hosts` | `SENTRIX_GATEWAY_HOSTS` | `localhost,127.0.0.1` | geçit sertifikasındaki adlar/IP'ler |
| `agent_dir` | `SENTRIX_AGENT_DIR` | – (imajda `/usr/share/sentrix/agents`) | `/download/` altında sunulan ajan ikili dosyaları |
| `offline_after` | `SENTRIX_OFFLINE_AFTER` | `60s` | bu süre boyunca iletişim olmazsa sunucu çevrimdışı sayılır |
| `heartbeat_interval` | `SENTRIX_HEARTBEAT_INTERVAL` | `15s` | ajanlara bildirilir |
| `agent_cert_validity` | `SENTRIX_AGENT_CERT_VALIDITY` | `8760h` | ajanlar, bitişten 30 gün önce otomatik olarak yeniler |
| `retention.raw` / `.minute` / `.hour` | `SENTRIX_RETENTION_RAW` / `_MINUTE` / `_HOUR` | `24h` / `168h` / `2160h` | katman başına metrik saklama süresi |
| `feeds.enabled` | `SENTRIX_FEEDS_ENABLED` | `true` | zafiyet veri kaynaklarını indirir |
| `feeds.interval` | `SENTRIX_FEEDS_INTERVAL` | `6h` | veri kaynağı yenileme aralığı |
| `feeds.stale_after` | `SENTRIX_FEEDS_STALE_AFTER` | `72h` | bu süreden sonra "veriler güncel değil" uyarısını gösterir |
| `feeds.nvd_api_key` | `SENTRIX_NVD_API_KEY` | – | isteğe bağlı NVD anahtarı (daha hızlı CVSS zenginleştirme) |
| `feeds.osv_base_url`, `debian_url`, `kev_url`, `epss_url`, `nvd_url` | `SENTRIX_OSV_BASE_URL`, … | resmi URL'ler | yansılar / internetten yalıtılmış kurulumlar |
| `language` | `SENTRIX_LANGUAGE` | `tr` | varsayılan dil: `tr` ya da `en`. Kullanıcı kendi dilini seçene kadar (kenar çubuğu, giriş sayfası, *Hesap* ayarları) arayüzde, bildirimlerde ise her zaman kullanılır |
| `agent_updates.mode` | `SENTRIX_AGENT_UPDATES` | `notify` | `off`, `notify` (eski ajanları gösterir) ya da `auto` (ajanlar kendini günceller); yöneticiler *Ayarlar → Kayıt* sayfasından değiştirebilir |
| `agent_updates.release_url` | `SENTRIX_AGENT_RELEASE_URL` | GitHub son sürüm | imzalı ajan sürümlerinin indirildiği adres; boş = yalnızca `agent_dir` içine konan sürümler |
| `agent_updates.interval` | `SENTRIX_AGENT_UPDATES_INTERVAL` | `6h` | sürüm kontrol aralığı |
| `log_level` | `SENTRIX_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `dev_insecure_cookies` | `SENTRIX_DEV_INSECURE_COOKIES` | `false` | üretimde asla kullanmayın |
| – | `SENTRIX_SECRET_KEY` | üretilen `secret.key` | depolanan sırlar için base64 kodlu 32 baytlık anahtar |

### Komutlar

```
sentrix-server serve | token create | ca-fingerprint | hosts | findings | stats | sync-feeds
               user create|reset-password | api-token create | audit | channel create | rule create
               healthcheck | version
```

## Ajan (`sentrix-agent`)

| YAML anahtarı | Ortam değişkeni | Varsayılan | Anlamı |
|---|---|---|---|
| `state_dir` | `SENTRIX_STATE_DIR` | `/var/lib/sentrix-agent` | kimlik, anahtar, sertifika, metrik arabelleği |
| `server_url` | `SENTRIX_SERVER_URL` | kayıttan gelir | geçit URL'si |
| `hostname` | `SENTRIX_HOSTNAME` | işletim sisteminin ana bilgisayar adı (ya da kayıtta `--hostname`) | bildirilen ana bilgisayar adı |
| `interval` | `SENTRIX_INTERVAL` | `10s` | metrik toplama aralığı |
| `send_interval` | `SENTRIX_SEND_INTERVAL` | `30s` | toplu gönderim aralığı |
| `buffer_max_mb` | `SENTRIX_BUFFER_MAX_MB` | `50` | sunucuya ulaşılamadığı sürece disk arabelleğinin üst sınırı |
| `inventory_interval` | `SENTRIX_INVENTORY_INTERVAL` | `6h` | tam envanter (ayrıca her yama/yenilemeden sonra) |
| `watch_services` | `SENTRIX_WATCH_SERVICES` | – | izlenecek systemd birimleri (arayüzde sunucu başına da ayarlanabilir) |
| `tls_endpoints` | `SENTRIX_TLS_ENDPOINTS` | – | sertifikası denetlenecek `host:port` adresleri (arayüzde sunucu başına da ayarlanabilir) |
| `allow_patching` | `SENTRIX_ALLOW_PATCHING` | `true` | `false` = salt okunur ajan (deneme çalıştırmaları yine çalışır) |
| `allow_self_update` | `SENTRIX_ALLOW_SELF_UPDATE` | `true` (.deb/.rpm'de `false`) | sunucunun önerdiği ajan sürümlerini kurar (yalnızca sürüm anahtarıyla imzalı dosyalar); `install.sh --no-self-update` `false` yapar |
| `proc_root` | `SENTRIX_PROC_ROOT` | `/proc` | sunucunun /proc dizini bağlanmış konteynerler için |
| `docker_socket` | `SENTRIX_DOCKER_SOCKET` | `/var/run/docker.sock` | varsa konteyner metrikleri |
| `log_level` | `SENTRIX_LOG_LEVEL` | `info` | |

Komutlar: `sentrix-agent enroll | run | inventory [--refresh] | version`.

## Dil

- **Arayüz:** her kullanıcı dilini (Türkçe ya da İngilizce) kenar çubuğundaki, giriş sayfasındaki ya da *Hesap*
  ayarlarındaki seçiciden seçer; seçim hesapta saklanır. O zamana kadar sunucunun varsayılan dili geçerlidir.
- **Sunucu varsayılanı:** `language: tr` / `SENTRIX_LANGUAGE=tr` (desteklenenler: `tr`, `en`; varsayılan `tr`).
  Bildirimler her zaman sunucunun varsayılan dilini kullanır.
- **Komut satırı araçları:** `SENTRIX_LANGUAGE` değerini izler (varsayılan `tr`).
- **Ajan kurulum betiği:** `install.sh --lang tr|en`.
