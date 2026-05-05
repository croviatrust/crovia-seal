# Crovia Seal - Browser Extension (MV3)

Sigilla e verifica output AI direttamente dentro ChatGPT, Claude, Gemini,
Perplexity - senza richiedere cooperazione dai vendor.

## Features inedite (originali Crovia, non plagiate)

### 1. Crovia Invisible Mark (CIM)
Il `seal_id` viene steganograficamente incorporato nell'output AI usando
caratteri Unicode a larghezza zero (`U+200B`, `U+200C` per bit 0/1,
`U+200D`/`U+FEFF` come marcatori, CRC-16 di integrita'). Copy/paste
preserva la marca. Chiunque abbia l'estensione puo' ri-verificare
l'origine dell'output anche fuori dal sito AI originale.

### 2. Universal Drop-Zone Verifier
`verify.html` e' una pagina stand-alone che accetta qualsiasi testo
(trascinato o incollato) e:
- estrae la CIM se presente;
- interroga il transparency log (fase successiva);
- mostra verdetto crittografico completo.

### 3. Local Issuer (privacy-first)
Alla prima apertura l'estensione genera un keypair Ed25519 nel tuo
browser. La chiave privata non esce mai. Ogni sigillo che emetti porta
la TUA identita' digitale. Nessun account, nessun server Crovia
coinvolto per l'emissione.

### 4. Attribution Ribbon (prossimo sprint)
Ribbon flottante sui campi editable: mentre scrivi/incolli, mostra in
tempo reale la percentuale di testo AI-sealed/human presente. Possibile
solo grazie alla CIM, nessun altro tool ne ha l'equivalente.

## Install

```bash
# Dal root del repo, dopo aver costruito @crovia/seal (reference TS):
cd crovia-seal/reference/typescript
npm install
npm run build

# Poi l'extension:
cd ../../integrations/browser-extension
npm install
npm run build
```

Poi in Chrome:
1. Apri `chrome://extensions`
2. Attiva "Modalita' sviluppatore"
3. "Carica estensione non pacchettizzata" -> seleziona la cartella `dist/`

## Test

```bash
npm test
```

Copre:
- **tests/stego.test.ts** - round-trip CIM su passaggi realistici,
  rilevamento tampering, rifiuto CRC invalido, overhead caratteri.
- **tests/issuer.test.ts** - generazione, persistenza simulata, sign/verify.
- **tests/storage.test.ts** - salvataggio e query dei seal emessi.

## Architettura

```
manifest.json (MV3)
+-- background.ts (service worker; firma i seal con la chiave locale)
+-- content/
|   +-- chatgpt.ts (detector sito-specifico)
|   +-- claude.ts, gemini.ts, perplexity.ts (prossimi sprint)
|   +-- index.ts (dispatcher per sito)
+-- popup/ (UI quick status)
+-- verify/ (pagina universal verifier)
+-- lib/
    +-- stego.ts          CIM encode/decode - INNOVAZIONE
    +-- issuer.ts         Gestione chiave locale Ed25519
    +-- storage.ts        IndexedDB per storia dei seal
    +-- messaging.ts      Protocollo content <-> service worker
```

## License

Apache 2.0.
