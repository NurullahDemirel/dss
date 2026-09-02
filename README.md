# DSS — Elektronik İmza Altyapısı

Bu depo, Avrupa Komisyonu’nun açık kaynak **Digital Signature Service (DSS) 6.5** çerçevesinin kopyasıdır. Amaç, mevcut sistemdeki **MA3 API / ESYA** bağımlılığını kaldırmak; **XAdES, CAdES ve PAdES** imza atma ve doğrulamayı kendi servisimizde yürütmektir.

DSS bir hazır ürün değil, Java kütüphanesidir. Üretimde PHP uygulaması bu repoyu doğrudan gömmez; DSS üstüne ince bir Java imza servisi konur, PHP o servisi REST ile çağırır.

| | Değer |
|---|---|
| Sürüm | 6.5 |
| Dil | Java 8+ (derleme için 11+, testli derleme için 15+) |
| Derleme | Maven 3.6.3+ |
| Lisans | LGPL 2.1 |
| Kaynak | [esig/dss](https://github.com/esig/dss) |
| Resmi dokümantasyon | [`dss-cookbook/src/main/asciidoc/dss-documentation.adoc`](dss-cookbook/src/main/asciidoc/dss-documentation.adoc) |

Demo uygulaması bu repoda yoktur. Ayrı projedir: [dss-demonstrations](https://github.com/esig/dss-demonstrations).

---

## Bu repo ne işe yarar, ne işe yaramaz

DSS şunları yapar:

- XAdES (XML), CAdES (CMS), PAdES (PDF) imza oluşturma
- İmza seviyesini yükseltme (B → T → LT → LTA)
- İmza, sertifika ve zaman damgası doğrulama
- PKCS#11 HSM / akıllı kart, PKCS#12
- OCSP, CRL, RFC 3161 zaman damgası
- REST ve SOAP uçları

DSS şunları yapmaz:

- Nitelikli sertifika basmak
- Milli Güvenli Sertifika Deposu’nu hazır getirmek (TR köklerini biz yükleriz)
- Mobil imza (Turkcell / Vodafone / TT)
- GİB e-fatura iş kuralları
- PHP / Vue istemcisi

5070 sayılı Kanun belirli bir kütüphaneyi zorunlu tutmaz. Zorunlu olan nitelikli sertifika, güvenli imza oluşturma aracı ve standart imza formatıdır.

---

## Hedef mimari (MA3 → DSS)

Mevcut sistemde imza MA3 ile atılıp doğrulanıyor. Hedef: aynı işi DSS ile yapmak.

```
PHP / Vue  (mevcut uygulama)
        │
        ▼
İmza Servisi  (Java, ince katman — henüz bu repoda yok)
        │
        ├─ HSM imza          PKCS#11  →  dss-token + dss-server-signing-rest
        ├─ Sözleşme PDF      getDataToSign → kartta imzala → signDocument
        └─ Doğrulama         dss-validation-rest  (kart gerekmez)
                │
                ├─ TR TrustStore   (Kamu SM ve diğer ESHS kökleri)
                ├─ OCSP / CRL      (dss-service)
                └─ TSA             (kullandığımız zaman damgası sunucusu)
```

Üretimde iki imza yolu vardır. Karıştırılmamalıdır:

1. **Sunucu imzası** — HSM. XAdES / CAdES / PAdES. Özel anahtar sunucuda kalır.
2. **Sözleşme PDF** — müşteri veya personel akıllı kartı. Özel anahtar sunucuya gelmez. DSS özeti üretir, kart imzalar, DSS PAdES belgesini birleştirir.

Doğrulama her iki yolda da kart istemez. Girdi imzalı belgedir; çıktı rapordur.

### MA3 profil eşlemesi

MA3 eski ETSI TS 101/102 isimlerini kullanır. DSS yeni Baseline profillerini üretir. Eski profilleri doğrulayabilir; yeni imzada Baseline kullanılır.

| MA3 | DSS |
|---|---|
| ES-BES | `XAdES_BASELINE_B` / `CAdES_BASELINE_B` / `PAdES_BASELINE_B` |
| ES-T | `*_BASELINE_T` |
| ES-XL | `*_BASELINE_LT` |
| ES-A | `*_BASELINE_LTA` |
| ES-C / ES-X | Doğrulama var; yeni imzada Baseline |

Byte-byte aynı imza beklenmez. Kabul ölçütü: DSS doğrulaması `TOTAL_PASSED` ve karşı tarafın (Adobe, mevcut doğrulayıcı, iç süreç) belgeyi kabul etmesi.

### Geçiş sırası

1. **Doğrulama paralel** — MA3 ile imzalanmış gerçek XAdES / CAdES / PAdES ve sözleşme PDF’leri DSS’e. Sonuçlar yan yana. PHP `dogrula` henüz MA3’te kalabilir.
2. **HSM imza** — Test HSM veya ayrı anahtar. XAdES, sonra CAdES, sonra PAdES.
3. **Sözleşme PDF** — Mevcut kart ajanı korunur; `getDataToSign` / `signDocument` DSS’e bağlanır.
4. **MA3 kapatılır.**

GİB e-belge ve mobil imza bu geçişin kapsamında değildir.

---

## Sistemin genel mantığı

### 1. Belge modeli

Her şey `DSSDocument` üzerinden akar (`dss-model`):

- `InMemoryDocument` — byte dizisi
- `FileDocument` — dosya
- `DigestDocument` — yalnızca özet (detached imza)

### 2. İmza oluşturma (3 adım)

DSS özel anahtarı kendisi kullanmaz. Anahtar `SignatureTokenConnection` üzerindedir (HSM, kart, PKCS#12). Servis yalnızca imza yapısını kurar.

```
1. getDataToSign(belge, parametreler)  →  ToBeSigned (imzalanacak baytlar)
2. token.sign(ToBeSigned, algoritma, anahtar)  →  SignatureValue
3. signDocument(belge, aynı parametreler, SignatureValue)  →  imzalı belge
```

HSM yolunda adım 2 sunucuda PKCS#11 ile biter (`Pkcs11SignatureToken` veya `dss-server-signing-rest`).

Kart yolunda adım 2 istemcide biter. Sunucu özeti gönderir, kart PIN ile imzalar, sunucu PAdES’i tamamlar. `getDataToSign` ve `signDocument` parametreleri (özellikle imza zamanı) birebir aynı olmalıdır.

Referans örnekler:

- XAdES: [`dss-cookbook/.../SignXmlXadesBTest.java`](dss-cookbook/src/test/java/eu/europa/esig/dss/cookbook/example/sign/SignXmlXadesBTest.java)
- PAdES: [`dss-cookbook/.../SignPdfPadesBTest.java`](dss-cookbook/src/test/java/eu/europa/esig/dss/cookbook/example/sign/SignPdfPadesBTest.java)
- HSM / uzak özet: [`dss-cookbook/.../ServerSignTest.java`](dss-cookbook/src/test/java/eu/europa/esig/dss/cookbook/example/sign/ServerSignTest.java)
- PKCS#11: [`dss-cookbook/.../PKCS11Snippet.java`](dss-cookbook/src/test/java/eu/europa/esig/dss/cookbook/example/snippets/PKCS11Snippet.java)

### 3. Doğrulama

Format söylenmez. `SignedDocumentValidator.fromDocument(belge)` uygun validator’ı seçer.

```
SignedDocumentValidator
        → CertificateVerifier  (kökler, OCSP, CRL, TSA)
        → validateDocument()
        → Reports
              ├─ SimpleReport     TOTAL_PASSED / INDETERMINATE / TOTAL_FAILED
              ├─ DetailedReport   kural kural gerekçe
              ├─ DiagnosticData   ham teknik veri
              └─ ETSI Validation Report
```

`INDETERMINATE` çoğu zaman bozuk imza değil, güven kökünün eksik olmasıdır. MA3’teki Milli Güvenli Sertifika Deposu’nun karşılığı `CommonTrustedCertificateSource` / PKCS#12 TrustStore’dur. TR kökleri yüklenmeden üretim doğrulaması yapılmaz.

Referans: [`dss-cookbook/.../ValidateSignedXmlXadesBTest.java`](dss-cookbook/src/test/java/eu/europa/esig/dss/cookbook/example/validate/ValidateSignedXmlXadesBTest.java)

### 4. REST uçları (PHP burayı çağırır)

| İş | Modül | Client arayüzü | Path |
|---|---|---|---|
| İmza özeti / belgeyi imzala / yükselt | `dss-signature-rest` | `RestDocumentSignatureService` | `getDataToSign`, `signDocument`, `extendDocument` |
| HSM’de özet imzala | `dss-server-signing-rest` | `RestSignatureTokenConnection` | `keys`, `sign`, `signDigest` |
| Belge doğrula | `dss-validation-rest` | `RestDocumentValidationService` | `validateSignature` |
| Sertifika doğrula | `dss-certificate-validation-rest` | `RestCertificateValidationService` | `validateCertificate` |

Postman koleksiyonu: [`dss-cookbook/src/main/postman`](dss-cookbook/src/main/postman)

Bu REST modülleri tek başına ayakta duran bir HTTP sunucusu değildir. JAX-RS arayüzleridir. Üretimde Spring Boot / Jakarta REST uygulamasına bağlanır (referans: dss-demonstrations).

---

## Modül haritası — hangisini kullanacağız

Tüm repo 100+ Maven modülüdür. Geçiş için gerekenler:

| Modül | Görev |
|---|---|
| `dss-xades` | XML imza / doğrulama |
| `dss-cades` | CMS imza / doğrulama |
| `dss-pades` + `dss-pades-pdfbox` | PDF imza / doğrulama |
| `dss-validation` | Ortak doğrulama motoru |
| `dss-token` | PKCS#11, PKCS#12, MS CAPI |
| `dss-service` | Online OCSP, CRL, TSA |
| `dss-utils-apache-commons` | Zorunlu utils uygulaması |
| `dss-signature-rest` | İmza REST |
| `dss-server-signing-rest` | HSM REST |
| `dss-validation-rest` | Doğrulama REST |
| `dss-cookbook` | Öğretici kod ve dokümantasyon |

Şimdilik gerekmeyenler (eIDAS 2.0 / JSON imza / SOAP): `dss-jades`, `dss-cb-ades`, `dss-attestation-*`, `dss-sd-jwt`, `dss-mdoc`, `*-soap*`.

Modül kataloğunun tam listesi: [`dss-cookbook/.../how-to-start-with-dss.adoc`](dss-cookbook/src/main/asciidoc/_chapters/how-to-start-with-dss.adoc) içindeki `MavenModules`.

Ana sınıflar:

| İş | Sınıf |
|---|---|
| XAdES servisi | `eu.europa.esig.dss.xades.signature.XAdESService` |
| CAdES servisi | `eu.europa.esig.dss.cades.signature.CAdESService` |
| PAdES servisi | `eu.europa.esig.dss.pades.signature.PAdESService` |
| Parametreler | `XAdESSignatureParameters`, `CAdESSignatureParameters`, `PAdESSignatureParameters` |
| HSM / kart | `eu.europa.esig.dss.token.Pkcs11SignatureToken` |
| PKCS#12 | `eu.europa.esig.dss.token.Pkcs12SignatureToken` |
| Doğrulayıcı | `eu.europa.esig.dss.validation.SignedDocumentValidator` |
| Sertifika doğrulama bağlamı | `eu.europa.esig.dss.spi.validation.CommonCertificateVerifier` |

---

## Test kodları nasıl bulunur

DSS’te iki katman test vardır. Geçişte ikisini de kullanırız.

### A. Cookbook — ilk okunacak yer

Öğretici, kısa, dokümana gömülü örnekler. Yeni geliştirici buradan başlar.

```
dss-cookbook/src/test/java/eu/europa/esig/dss/cookbook/example/
├── sign/          imza atma
├── validate/      doğrulama
├── snippets/      PKCS#11, OCSP, CRL, REST, TrustStore
│   └── ws/rest/   REST client örnekleri
├── sources/       DSSDocument, TSA
└── timestamp/     zaman damgası
```

Geçiş için öncelikli dosyalar:

| Ne arıyorsun | Dosya |
|---|---|
| XML imzala | `sign/SignXmlXadesBTest.java`, `SignXmlXadesLTTest.java`, `SignXmlXadesTWithOnlineSourceTest.java` |
| PDF imzala | `sign/SignPdfPadesBTest.java`, `SignPdfPadesBVisibleTest.java` |
| CAdES / CMS | `sign/SignXmlCadesBTest.java` |
| Seviye yükselt | `sign/ExtendXAdESTest.java` |
| Çoklu imza | `sign/MultipleSignXadesBTest.java`, `MultipleSignPadesBTest.java` |
| Doğrula | `validate/ValidateSignedXmlXadesBTest.java`, `SignatureLevelValidationTest.java` |
| PKCS#11 | `snippets/PKCS11Snippet.java` |
| HSM özet imza | `sign/ServerSignTest.java` |
| REST imza | `snippets/ws/rest/RestSignatureServiceSnippet.java` |
| REST doğrulama | `snippets/ws/rest/RestValidationServiceSnippet.java` |
| REST HSM | `snippets/ws/rest/RestServerSigningServiceSnippet.java` |
| TrustStore / TL | `snippets/TLValidationJobSnippets.java` |
| OCSP / CRL | `snippets/OCSPSourceSnippet.java`, `CRLSourceSnippet.java` |

Cookbook testlerini çalıştırma:

```bash
mvn test -pl dss-cookbook -Dtest=SignXmlXadesBTest,SignPdfPadesBTest,ValidateSignedXmlXadesBTest
```

### B. Format modülleri — gerçek davranış ve edge case

Her format kendi `src/test` altında yüzlerce senaryo taşır. Klasörler aynı kalıptadır:

```
dss-xades/src/test/java/.../xades/
dss-cades/src/test/java/.../cades/
dss-pades/src/test/java/.../pades/
dss-pades-pdfbox/src/test/java/...
```

| Klasör | Anlamı |
|---|---|
| `signature/` | İmza oluşturma (Level B/T/LT/LTA, enveloped/detached, RSA/ECDSA) |
| `validation/` | Hazır imzalı örnekleri doğrulama |
| `extension/` | B→T, T→LT, LT→LTA yükseltme |
| `requirements/` | Baseline profil zorunlulukları |

Örnek aramalar:

```bash
# PAdES B seviyesi imza testleri
find dss-pades/src/test -name '*PAdESLevelB*'

# XAdES doğrulama
find dss-xades/src/test -path '*validation*' -name '*Test.java'

# CAdES LTA
find dss-cades/src/test -name '*LTA*'
```

Tek test:

```bash
mvn test -pl dss-xades -Dtest=XAdESLevelBDetachedTest
mvn test -pl dss-cades -Dtest=CAdESLevelBWithRSATest
mvn test -pl dss-pades-pdfbox -Dtest=PAdESLevelBTest
```

İmzalı örnek belgeler (doğrulama altın seti için kaynak):

```
dss-xades/src/test/resources/validation/
dss-cades/src/test/resources/validation/
dss-pades/src/test/resources/
dss-cookbook/src/test/resources/
```

### C. Geçişe özel altın set (biz ekleyeceğiz)

DSS’in kendi testleri sahte PKI kullanır. Üretim kararı için MA3 ile üretilmiş gerçek belgeler gerekir:

1. MA3 XAdES / CAdES / PAdES örnekleri (geçerli, süresi dolmuş, iptal, çoklu imza, sözleşme PDF)
2. Aynı dosyayı DSS `SignedDocumentValidator` ile doğrula
3. SimpleReport `Indication` değerlerini karşılaştır ve sapmayı kaydet

Bu klasör henüz yok; Faz 1’de `dss-cookbook/src/test/resources/tr-golden/` (veya ayrı bir test modülü) olarak eklenecek.

---

## Derleme

İlk kurulumda test sınıflarına bağımlı modüller vardır. İlk derleme:

```bash
mvn clean install -Pquick-init
```

Günlük hızlı derleme (test yok):

```bash
mvn clean install -Pquick
```

Tam test (1 saatten uzun sürebilir):

```bash
mvn clean install
```

Sadece bizim formatlar:

```bash
mvn test -pl dss-xades,dss-cades,dss-pades,dss-pades-pdfbox,dss-validation,dss-token,dss-cookbook
```

Maven Central’dan kütüphane olarak kullanmak (ayrı bir Java servis projesi için):

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>eu.europa.ec.joinup.sd-dss</groupId>
            <artifactId>dss-bom</artifactId>
            <version>6.5</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

`jakarta.*` (DSS 6.x) kullanılır. Eski `javax.*` uygulama `5.13.1` ister; yeni serviste 6.5 kalır.

---

## PHP entegrasyon notu

PHP tarafında `then` içinde return yok; servis fonksiyonu çağrılır, state komponentte tutulur. Başarı HTTP status ile karar verilir.

Beklenen akış:

1. Vue formu / belge seçimi
2. PHP, Java imza servisine POST
3. Status 2xx ise imzalı belge veya SimpleReport state’e yazılır
4. Hata body’si kullanıcıya gösterilir; `INDETERMINATE` teknik olarak 2xx olabilir, Indication ayrıca okunur

---

## Bilinen sınırlar (Türkiye)

- AB Trusted List otomatik gelir; **Türkiye listede yoktur**. Kamu SM ve kullanılan ESHS kökleri TrustStore’a elle konur.
- eIDAS `QESIG` etiketi TR sertifikasında otomatik çıkmaz. Teknik geçerlilik `TOTAL_PASSED`; yasal nitelik 5070 yorumudur.
- AKİS APDU hızlandırması yoktur. Kart/HSM PKCS#11 sunuyorsa yeter.
- Sözleşme PDF’sinde tarayıcı karta erişemez. Yerel ajan (bugünkü MA3 istemci modeli) kalır.
- DSS demo sahte TSA kullanır. Üretimde kendi TSA bağlanır.

---

## Dokümantasyon indeksi

| Konu | Dosya |
|---|---|
| Tam kılavuz | [`dss-cookbook/src/main/asciidoc/dss-documentation.adoc`](dss-cookbook/src/main/asciidoc/dss-documentation.adoc) |
| Başlangıç / modüller | [`_chapters/how-to-start-with-dss.adoc`](dss-cookbook/src/main/asciidoc/_chapters/how-to-start-with-dss.adoc) |
| İmza oluşturma | [`_chapters/signature-creation.adoc`](dss-cookbook/src/main/asciidoc/_chapters/signature-creation.adoc) |
| Doğrulama | [`_chapters/signature-validation.adoc`](dss-cookbook/src/main/asciidoc/_chapters/signature-validation.adoc) |
| REST / SOAP | [`_chapters/webservices.adoc`](dss-cookbook/src/main/asciidoc/_chapters/webservices.adoc) |
| eIDAS nitelik | [`_chapters/eIDAS.adoc`](dss-cookbook/src/main/asciidoc/_chapters/eIDAS.adoc) |
| Politika XML | [`dss-policy-jaxb/src/main/resources/policy/constraint.xml`](dss-policy-jaxb/src/main/resources/policy/constraint.xml) |

Dokümanı HTML üretmek:

```bash
mvn clean install -pl dss-cookbook -P asciidoctor
```

Çevrimiçi JavaDoc: [DSS API docs](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/apidocs/index.html)

---

## Lisans

DSS çekirdeği **GNU LGPL 2.1** ile gelir. Kütüphaneyi ayrı bir servis olarak kullanmak ticari üründe uygundur. DSS kaynak kodunu değiştirirseniz o değişiklikler LGPL yükümlülüğüne girer. PHP uygulaması ve ince Java katmanı ayrı kalabilir; hukuki teyit ayrı alınır.
