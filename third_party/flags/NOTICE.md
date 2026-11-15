# Country flag images notice

FuzeVPN bundles one flag image per country code, so that a location added by
the service shows its flag without an application update. The images are
shipped unmodified in the Flutter asset bundle as `assets/flags/<code>.png`.

Source archive: https://flagcdn.com/w160.zip
Publisher: Flagpedia (https://flagpedia.net), 160-pixel-wide PNG set
Downloaded: 2026-11-12
Archive SHA-256: 37b432035a82b551f83ca8b614d3bc19b68917213d552aa95728a2da39f0f850
Archive size: 255483 bytes, 254 PNG members
Bundled: 250 files, 215419 bytes, each named after its lower-case two-letter
code: the 249 ISO 3166-1 alpha-2 codes and `xk` (Kosovo, user-assigned code)
Not bundled: `gb-eng`, `gb-nir`, `gb-sct` and `gb-wls`, which are not country
codes

The archive digest was computed locally after the download; no independently
published digest was checked. See download-provenance.json. Every bundled file
is listed with its SHA-256 in payload-sha256.json. `test/country_flag_test.dart`
fails when `assets/flags` differs from that list or from the code set compiled
into the application (`lib/country_flag_assets.dart`).

## Licence

Flagpedia states that its flag images are in the public domain, free for
commercial and non-commercial use, and that attribution is not required. The
images are based on the vector files of Wikimedia Commons. No licence text has
to accompany them; this notice records where the files come from.

## Updating

Download the same archive, record its new digest and date here and in
download-provenance.json, check every PNG (signature, 160-pixel width) before
copying it, regenerate payload-sha256.json and update
`bundledCountryFlagCodes` in `lib/country_flag_assets.dart`. Keep every other
file out of `assets/flags`: the whole directory ships in the application.
