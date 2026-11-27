**Türkçe** · [English](CONTRIBUTING.md)

# Sentrix'e katkıda bulunma

İlginiz için teşekkürler! Hata bildirimleri, belge düzeltmeleri ve pull request'ler memnuniyetle karşılanır.

## Geliştirme

```bash
make build test lint     # Go 1.26+, golangci-lint v2
make race                # race detector (CI runs it)
make run-server          # dev server: http://localhost:18080 (deploy/dev/server.yaml)
go run ./test/tools/fakefleet   # six simulated hosts for UI work
make css                 # rebuild Tailwind after template changes (Node.js)
```

`make race` yarış dedektörüyle test eder (CI'da çalışır); `make run-server` geliştirme sunucusunu
http://localhost:18080 adresinde başlatır; `fakefleet` arayüz çalışmaları için altı benzetimli sunucu sağlar;
`make css` şablon değişikliklerinden sonra Tailwind'i yeniden derler (Node.js gerekir).

Yalnızca Linux'a özgü davranışlar (toplayıcılar, paket yöneticileri), fixture testleriyle ve CI'da gerçek Linux
üzerinde ve dağıtım konteynerlerinde çalışan `test/acceptance/` içindeki kabul betikleriyle kapsanır.

## Yönergeler

- Ajanın eylem kümesini kapalı tutun: yeni yetenekler yeni bir tipli eylem, katı parametre doğrulaması ve hatalı
  girdinin hiçbir şey çalışmadan reddedildiğini kanıtlayan testler gerektirir.
- Paket sürümlerini asla dize ya da semver mantığıyla karşılaştırmayın — `internal/vuln/version` kullanın.
- Birim testleri canlı veri kaynaklarına erişmemelidir; `test/fixtures/` altına küçük fixture'lar ekleyin.
- `internal/vuln` ve `internal/patch` içindeki dışa aktarılan tanımlayıcılar doc yorumları gerektirir.
- Conventional Commits kullanın (`feat(agent): …`, `fix(server): …`). Önemli tasarım kararlarını
  `docs/DECISIONS.md` dosyasına kaydedin.
- Arayüz metinleri `web/i18n/tr` ve `web/i18n/en` kataloglarında tutulur; yeni bir metin eklediğinizde her iki dile
  de ekleyin.
- Güvenlik sorunları: bkz. [SECURITY.tr.md](SECURITY.tr.md) — lütfen gizli olarak bildirin.

Katkıda bulunarak katkılarınızın Apache License 2.0 altında lisanslandığını kabul etmiş olursunuz.
